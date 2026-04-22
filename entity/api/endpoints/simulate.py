"""POST /simulate — Banishing Ritual.

Cost: $2.00 USDC. Inputs: `{chain_id, address, context?}`. Returns
defensive advice + a list of recommended actions (e.g. "revoke at
revoke.cash", "pause forwarder").

Strategy: synthesise a Triaged event with the user's optional context as
extra signal evidence, run the Reasoner with hint biased toward
remediation, then translate the verdict into actionable advice.
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from ...cognition.reasoner import Reasoner
from ...cognition.types import ThreatClass
from ...perception.aggregator import Priority, Triaged
from ...perception.types import EventSource, PerceptionEvent, RiskSignal
from ..x402 import (
    PaymentVerification,
    PaymentVerifier,
    require_payment,
    settled_response,
)

router = APIRouter()


class SimulateRequest(BaseModel):
    chain_id: int = Field(..., examples=[8453])
    address: str = Field(..., pattern=r"^0x[0-9a-fA-F]{40}$")
    context: str | None = None


REMEDIATION: dict[ThreatClass, list[str]] = {
    ThreatClass.HONEYPOT:           ["do_not_interact", "warn_holders"],
    ThreatClass.PHISHING_APPROVAL:  ["revoke_via_revoke_cash", "warn_holders"],
    ThreatClass.RUGPULL:            ["reduce_exposure", "monitor_liquidity"],
    ThreatClass.EXPLOIT_CONTRACT:   ["pause_interaction", "await_patch"],
    ThreatClass.GOVERNANCE_ATTACK:  ["review_pending_proposals", "delay_voting"],
    ThreatClass.PROMPT_INJECTION:   ["isolate_input", "audit_downstream_agents"],
    ThreatClass.UNKNOWN:            ["watch_and_wait"],
    ThreatClass.BENIGN:             [],
}


def make_simulate_router(
    *,
    reasoner: Reasoner,
    verifier: PaymentVerifier,
    recipient: str,
) -> APIRouter:
    pay = require_payment(
        asset="USDC", amount_usd=2.00,
        recipient=recipient, verifier=verifier,
    )

    @router.post("/simulate")
    async def simulate(
        body: SimulateRequest, payment: PaymentVerification = Depends(pay)
    ) -> Any:
        triaged = _synthetic_triaged(body.chain_id, body.address, body.context)
        verdict = await reasoner.reason(triaged)
        threat = verdict.threat
        actions = REMEDIATION.get(threat.threat_class, [])

        return settled_response(
            {
                "threat_class": threat.threat_class.value,
                "advice":       verdict.reasoning or threat.summary,
                "actions":      actions,
                "confidence":   threat.confidence,
                "endpoint":     "simulate",
            },
            payment,
        )

    return router


def _synthetic_triaged(
    chain_id: int, address: str, context: str | None
) -> Triaged:
    addr = address.lower()
    payload: dict[str, Any] = {
        "to": addr,
        "chain_id": chain_id,
        "simulate_request": True,
    }
    if context:
        payload["context"] = context

    evt = PerceptionEvent(
        source=EventSource.CHAIN_TX,
        observed_at=datetime.now(UTC),
        identifier=f"simulate:{chain_id}:{addr}",
        payload=payload,
        signals=(
            RiskSignal("simulate_request", 0.60, "explicit user remediation request"),
        ),
    )
    return Triaged(priority=Priority.HIGH, subject=f"addr:{addr}", events=(evt,))
