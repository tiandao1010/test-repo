"""End-to-end Reasoner test with a stub brain.

No network. The brain returns a canned JSON object; we assert that the
reasoner parses it into a ReasonedVerdict and (when confidence high
enough) writes it back to memory.
"""
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from entity.cognition.brains.stub import StubBrain
from entity.cognition.memory import InMemoryStore, RecordKind, StubEmbedder
from entity.cognition.prompts.loader import default_loader
from entity.cognition.reasoner import Reasoner, ReasonerConfig
from entity.cognition.router import Router
from entity.cognition.types import ThreatClass
from entity.perception.aggregator import Priority, Triaged
from entity.perception.types import EventSource, PerceptionEvent, RiskSignal

REPO_ROOT = Path(__file__).resolve().parents[1]


def _triaged() -> Triaged:
    evt = PerceptionEvent(
        source=EventSource.CHAIN_TX,
        observed_at=datetime(2026, 4, 22, tzinfo=UTC),
        identifier="0xtx",
        payload={"to": "0xdead", "value_wei": 0},
        signals=(RiskSignal("contract_deployment", 0.6, "deploy"),),
    )
    goplus = PerceptionEvent(
        source=EventSource.INTEL_GOPLUS,
        observed_at=datetime(2026, 4, 22, tzinfo=UTC),
        identifier="goplus:8453:0xdead",
        payload={"token_address": "0xdead"},
        signals=(RiskSignal("goplus:honeypot", 0.95, "is_honeypot=1"),),
    )
    return Triaged(priority=Priority.HIGH, subject="addr:0xdead", events=(evt, goplus))


def _make_reasoner(stub_text: str, *, persist: bool = True) -> tuple[Reasoner, InMemoryStore]:
    bundle = default_loader(REPO_ROOT).load()
    brain = StubBrain(name="claude:opus", responder=lambda s, u: stub_text)
    router = Router(brains=[brain])
    memory = InMemoryStore(StubEmbedder(dim=64))
    reasoner = Reasoner(
        prompts=bundle,
        router=router,
        memory=memory,
        config=ReasonerConfig(persist_verdicts=persist, min_confidence_to_persist=0.5),
    )
    return reasoner, memory


async def test_reasoner_parses_well_formed_json():
    canned = (
        '{"threat_class": "honeypot", "severity": 87, "confidence": 0.92, '
        '"summary": "live honeypot on Base", '
        '"reasoning": "GoPlus is_honeypot flag corroborates a fresh deployment.", '
        '"evidence": ["goplus:honeypot", "contract_deployment"]}'
    )
    reasoner, memory = _make_reasoner(canned)
    verdict = await reasoner.reason(_triaged())

    assert verdict.threat.threat_class is ThreatClass.HONEYPOT
    assert verdict.threat.severity == 87
    assert 0.9 <= verdict.threat.confidence <= 1.0
    assert verdict.brain == "claude:opus"
    assert "0xtx" in verdict.threat.chain_refs

    # high-confidence threat should land in memory
    assert len(memory) == 1


async def test_reasoner_handles_malformed_brain_response_without_crashing():
    reasoner, memory = _make_reasoner("not json at all, sorry")
    verdict = await reasoner.reason(_triaged())

    assert verdict.threat.threat_class is ThreatClass.UNKNOWN
    assert verdict.threat.confidence == 0.0
    assert "unparseable" in verdict.threat.summary

    # benign / unknown verdicts must NOT pollute memory
    assert len(memory) == 0


async def test_reasoner_clamps_out_of_range_values():
    canned = (
        '{"threat_class": "honeypot", "severity": 9999, "confidence": 5.0, '
        '"summary": "x", "reasoning": "y", "evidence": []}'
    )
    reasoner, _ = _make_reasoner(canned, persist=False)
    verdict = await reasoner.reason(_triaged())
    assert verdict.threat.severity == 100
    assert verdict.threat.confidence == 1.0


async def test_reasoner_uses_memory_in_scratchpad():
    """Past similar threats should be retrieved before reasoning."""
    captured_systems: list[str] = []

    def capture(system: str, user: str) -> str:
        captured_systems.append(system)
        return '{"threat_class": "honeypot", "severity": 60, "confidence": 0.7, ' \
               '"summary": "x", "reasoning": "y", "evidence": []}'

    bundle = default_loader(REPO_ROOT).load()
    memory = InMemoryStore(StubEmbedder(dim=64))
    # seed with a similar record
    from entity.cognition.memory import MemoryRecord
    await memory.save(MemoryRecord(
        kind=RecordKind.THREAT,
        subject="addr:0xpast",
        summary="prior honeypot on Base",
        body="full body about honeypot",
    ))

    brain = StubBrain(name="claude:opus", responder=capture)
    reasoner = Reasoner(
        prompts=bundle,
        router=Router(brains=[brain]),
        memory=memory,
    )
    await reasoner.reason(_triaged())
    assert any("prior honeypot" in s for s in captured_systems)
