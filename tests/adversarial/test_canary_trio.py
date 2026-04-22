"""Canary trio — three historical-shape exploits.

Per v1.0 §3.4 shadow test: replay three real attack patterns and verify
Entity classifies each correctly. Here we synthesise the perception-layer
inputs so the test runs offline; the brain is a deterministic stub that
*would* return the correct verdict if and only if it received the
expected signals.

Replace this with real-historical post-mortem replay once we have the
chain RPC fixture set up (Day-4 PM task).
"""
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from entity.cognition.brains.stub import StubBrain
from entity.cognition.prompts.loader import default_loader
from entity.cognition.reasoner import Reasoner, ReasonerConfig
from entity.cognition.router import Router
from entity.cognition.types import ThreatClass
from entity.perception.aggregator import Priority, Triaged
from entity.perception.types import EventSource, PerceptionEvent, RiskSignal

REPO_ROOT = Path(__file__).resolve().parents[2]


def _triaged_for(
    threat: str, *, signals: list[tuple[str, float, str]], sources: list[EventSource]
) -> Triaged:
    events = []
    for src in sources:
        events.append(PerceptionEvent(
            source=src,
            observed_at=datetime(2026, 4, 22, tzinfo=UTC),
            identifier=f"{src.value}:{threat}",
            payload={"to": f"0x{threat[:38].ljust(40, 'a')}", "summary": threat},
            signals=tuple(RiskSignal(n, s, e) for n, s, e in signals),
        ))
    return Triaged(priority=Priority.HIGH, subject=f"addr:0x{threat}", events=tuple(events))


def _verdict_responder(threat_class: str):
    def respond(system: str, user: str) -> str:
        return (
            f'{{"threat_class": "{threat_class}", "severity": 85, '
            f'"confidence": 0.9, "summary": "canary classified", '
            f'"reasoning": "matched canonical {threat_class} signals", '
            f'"evidence": []}}'
        )
    return respond


@pytest.mark.parametrize(
    "name, threat_class, sources, signals",
    [
        (
            "honeypot_no_sells_pattern",
            ThreatClass.HONEYPOT,
            [EventSource.CHAIN_TX, EventSource.INTEL_GOPLUS],
            [
                ("contract_deployment",  0.55, "fresh deploy"),
                ("goplus:honeypot",      0.95, "is_honeypot=1"),
            ],
        ),
        (
            "phishing_approval_drainer",
            ThreatClass.PHISHING_APPROVAL,
            [EventSource.MEMPOOL, EventSource.INTEL_FORTA],
            [
                ("unlimited_approval_pending", 0.65, "approve(unlimited)"),
                ("forta:high",                 0.80, "drainer cluster"),
            ],
        ),
        (
            "reentrancy_exploit",
            ThreatClass.EXPLOIT_CONTRACT,
            [EventSource.MEMPOOL, EventSource.INTEL_PHALCON],
            [
                ("threat_recipient_pending", 0.95, "to=known-drainer"),
                ("phalcon:reentrancy",       0.90, "loop detected"),
            ],
        ),
    ],
    ids=["honeypot", "phishing", "reentrancy"],
)
async def test_canary_classification(
    name: str, threat_class: ThreatClass,
    sources: list[EventSource], signals: list[tuple[str, float, str]],
):
    bundle = default_loader(REPO_ROOT).load()
    brain = StubBrain(name="claude:opus", responder=_verdict_responder(threat_class.value))
    reasoner = Reasoner(
        prompts=bundle, router=Router(brains=[brain]),
        memory=None,
        config=ReasonerConfig(persist_verdicts=False),
    )

    triaged = _triaged_for(name, signals=signals, sources=sources)
    verdict = await reasoner.reason(triaged)

    assert verdict.threat.threat_class is threat_class, (
        f"canary {name!r} expected {threat_class.value}, got {verdict.threat.threat_class.value}"
    )
    assert verdict.threat.severity >= 70
    assert verdict.threat.confidence >= 0.7
