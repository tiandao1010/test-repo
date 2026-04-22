"""Runtime loop wiring: aggregator → reasoner → sinks."""
from __future__ import annotations

from datetime import UTC, datetime

from entity.cognition.brains.stub import StubBrain
from entity.cognition.types import ReasonedVerdict
from entity.perception.aggregator import Aggregator, Priority, Triaged
from entity.perception.types import EventSource, PerceptionEvent, RiskSignal
from entity.runtime.main import EntityLoop
from entity.runtime.reasoner_factory import build_default_reasoner

T0 = datetime(2026, 4, 22, tzinfo=UTC)
ADDR = "0xdead000000000000000000000000000000beef01"


async def _events():
    yield PerceptionEvent(
        source=EventSource.CHAIN_TX, observed_at=T0,
        identifier="0xtx1", payload={"to": ADDR},
        signals=(RiskSignal("contract_deployment", 0.6, "deploy"),),
    )
    yield PerceptionEvent(
        source=EventSource.INTEL_GOPLUS, observed_at=T0,
        identifier=f"goplus:8453:{ADDR}",
        payload={"token_address": ADDR},
        signals=(RiskSignal("goplus:honeypot", 0.95, "is_honeypot=1"),),
    )
    yield PerceptionEvent(
        source=EventSource.CHAIN_TX, observed_at=T0,
        identifier="0xtx_quiet", payload={"to": "0xfeed00000000000000000000000000000000feed"},
        signals=(RiskSignal("low", 0.2, "noise"),),
    )


async def test_loop_emits_verdict_per_qualifying_subject():
    canned = (
        '{"threat_class": "honeypot", "severity": 80, "confidence": 0.9, '
        '"summary": "honeypot", "reasoning": "rule", "evidence": []}'
    )
    brain = StubBrain(name="claude:sonnet", responder=lambda s, u: canned)
    reasoner = build_default_reasoner(brains=[brain])
    aggregator = Aggregator()
    sunk: list[tuple[ReasonedVerdict, Triaged]] = []

    async def sink(v, t):
        sunk.append((v, t))

    loop = EntityLoop(
        aggregator=aggregator,
        reasoner=reasoner,
        sinks=[sink],
        min_priority=Priority.MEDIUM,
    )
    await loop.run(_events())

    # at minimum the corroborated honeypot should produce a verdict
    addrs = [t.subject for _, t in sunk]
    assert any(s == f"addr:{ADDR}" for s in addrs)
    high = [v for v, t in sunk if t.priority is Priority.HIGH]
    assert any(v.threat.threat_class.value == "honeypot" for v in high)


async def test_loop_skips_below_threshold():
    """min_priority=HIGH should filter out MEDIUM-only subjects."""
    brain = StubBrain(name="claude:sonnet")
    reasoner = build_default_reasoner(brains=[brain])
    sunk = []

    async def sink(v, t):
        sunk.append((v, t))

    loop = EntityLoop(
        aggregator=Aggregator(),
        reasoner=reasoner,
        sinks=[sink],
        min_priority=Priority.HIGH,
    )
    await loop.run(_events())

    # only the corroborated honeypot is HIGH; everything else is filtered
    assert all(t.priority is Priority.HIGH for _, t in sunk)
