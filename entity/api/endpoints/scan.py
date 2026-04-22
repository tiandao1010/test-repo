"""POST /scan — Elder Sign Threat Scanner.

Cost: $0.50 USDC. Input: `{chain_id, address}`. Output: threat verdict.

Implementation strategy: synthesise a `Triaged` perception event
representing "we are explicitly being asked about this contract" and
push it through the Reasoner. The reasoner already knows how to enrich
with memory and pick a brain.
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from ...cognition.reasoner import Reasoner
from ...perception.aggregator import Priority, Triaged
from ...perception.types import EventSource, PerceptionEvent, RiskSignal
from ..x402 import (
    PaymentVerification,
    PaymentVerifier,
    require_payment,
    settled_response,
)

router = APIRouter()


class ScanRequest(BaseModel):
    chain_id: int = Field(..., examples=[8453])
    address: str = Field(..., pattern=r"^0x[0-9a-fA-F]{40}$")


def make_scan_router(
    *,
    reasoner: Reasoner,
    verifier: PaymentVerifier,
    recipient: str,
) -> APIRouter:
    pay = require_payment(
        asset="USDC", amount_usd=0.50,
        recipient=recipient, verifier=verifier,
    )

    @router.post("/scan")
    async def scan(
        body: ScanRequest, payment: PaymentVerification = Depends(pay)
    ) -> Any:
        triaged = _synthetic_triaged(body.chain_id, body.address)
        verdict = await reasoner.reason(triaged)
        threat = verdict.threat
        return settled_response(
            {
                "threat_class": threat.threat_class.value,
                "severity":     threat.severity,
                "confidence":   threat.confidence,
                "summary":      threat.summary,
                "evidence":     list(threat.evidence),
                "chain_refs":   list(threat.chain_refs),
                "endpoint":     "scan",
            },
            payment,
        )

    return router


def _synthetic_triaged(chain_id: int, address: str) -> Triaged:
    addr = address.lower()
    evt = PerceptionEvent(
        source=EventSource.CHAIN_TX,
        observed_at=datetime.now(UTC),
        identifier=f"scan:{chain_id}:{addr}",
        payload={"to": addr, "chain_id": chain_id, "scan_request": True},
        signals=(RiskSignal("scan_request", 0.50, "explicit user scan request"),),
    )
    return Triaged(priority=Priority.MEDIUM, subject=f"addr:{addr}", events=(evt,))
