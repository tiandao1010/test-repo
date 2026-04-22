"""Aggregator pre-filter tests.

The aggregator is the choke point that bounds LLM cost. These tests
pin the spec from v1.0 §3.2: >=2 sources → HIGH, 1 source → MEDIUM,
otherwise DROP. They also pin the dedupe window and the heartbeat
behaviour for CHAIN_BLOCK.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from entity.perception.aggregator import (
    Aggregator,
    AggregatorConfig,
    Priority,
)
from entity.perception.types import EventSource, PerceptionEvent, RiskSignal

T0 = datetime(2026, 4, 22, 12, 0, 0, tzinfo=UTC)
ADDR = "0xbad0000000000000000000000000000000000000"


def _evt(
    source: EventSource,
    *,
    score: float = 0.7,
    payload: dict | None = None,
    identifier: str = "evt-1",
    at: datetime = T0,
) -> PerceptionEvent:
    return PerceptionEvent(
        source=source,
        observed_at=at,
        identifier=identifier,
        payload=payload or {"to": ADDR},
        signals=(RiskSignal("test", score, "synthetic"),),
    )


def test_block_heartbeat_is_not_aggregated():
    agg = Aggregator()
    evt = _evt(EventSource.CHAIN_BLOCK, payload={}, identifier="42")
    assert agg.ingest(evt) is None
    assert agg.open_subjects == 0


def test_single_source_above_medium_threshold_is_medium():
    agg = Aggregator(AggregatorConfig(medium_min_risk=0.5))
    triaged = agg.ingest(_evt(EventSource.CHAIN_TX, score=0.7))
    assert triaged is not None
    assert triaged.priority is Priority.MEDIUM
    assert triaged.subject == f"addr:{ADDR}"


def test_single_source_below_medium_threshold_is_drop():
    agg = Aggregator(AggregatorConfig(medium_min_risk=0.5))
    triaged = agg.ingest(_evt(EventSource.CHAIN_TX, score=0.3))
    assert triaged is not None
    assert triaged.priority is Priority.DROP


def test_two_independent_sources_on_same_address_become_high():
    agg = Aggregator()
    chain_evt = _evt(EventSource.CHAIN_TX, identifier="0xtx1")
    goplus_evt = _evt(
        EventSource.INTEL_GOPLUS,
        identifier=f"goplus:8453:{ADDR}",
        payload={"token_address": ADDR},
    )

    first = agg.ingest(chain_evt)
    second = agg.ingest(goplus_evt)

    assert first is not None and first.priority is Priority.MEDIUM
    assert second is not None and second.priority is Priority.HIGH
    assert second.sources == {EventSource.CHAIN_TX, EventSource.INTEL_GOPLUS}


def test_same_source_repeated_does_not_promote():
    """Two CHAIN_TX events on the same addr is still ONE source — stays MEDIUM."""
    agg = Aggregator()
    a = agg.ingest(_evt(EventSource.CHAIN_TX, identifier="0xtx1"))
    b = agg.ingest(_evt(EventSource.CHAIN_TX, identifier="0xtx2"))
    assert a is not None and b is not None
    assert b.priority is Priority.MEDIUM
    assert b.sources == {EventSource.CHAIN_TX}


def test_forta_uses_first_address_as_subject():
    agg = Aggregator()
    chain_evt = _evt(EventSource.CHAIN_TX)
    forta_evt = _evt(
        EventSource.INTEL_FORTA,
        identifier="forta-hash-1",
        payload={"addresses": [ADDR, "0xother"], "severity": "HIGH"},
    )
    agg.ingest(chain_evt)
    triaged = agg.ingest(forta_evt)
    assert triaged is not None
    assert triaged.priority is Priority.HIGH


def test_phalcon_tx_subject_matches_chain_tx_subject():
    """When both flag the same tx hash, that should corroborate."""
    agg = Aggregator()
    tx_hash = "0xabc123"
    chain = PerceptionEvent(
        source=EventSource.CHAIN_TX,
        observed_at=T0,
        identifier=tx_hash,
        payload={"to": None},  # contract deployment, no addr
        signals=(RiskSignal("contract_deployment", 0.55, "deploy"),),
    )
    phalcon = PerceptionEvent(
        source=EventSource.INTEL_PHALCON,
        observed_at=T0,
        identifier=f"phalcon:8453:{tx_hash}",
        payload={"tx_hash": tx_hash},
        signals=(RiskSignal("phalcon:reentrancy", 0.9, "loop"),),
    )
    agg.ingest(chain)
    triaged = agg.ingest(phalcon)
    assert triaged is not None
    assert triaged.priority is Priority.HIGH


def test_dedupe_window_evicts_stale_subjects():
    agg = Aggregator(AggregatorConfig(dedupe_window_s=60))
    agg.ingest(_evt(EventSource.CHAIN_TX, at=T0))
    assert agg.open_subjects == 1

    later = T0 + timedelta(seconds=120)
    agg.ingest(
        _evt(
            EventSource.CHAIN_TX,
            payload={"to": "0xfeedbeef00000000000000000000000000000000"},
            at=later,
        )
    )
    assert agg.open_subjects == 1  # old one evicted, new one added


async def test_stream_yields_only_high_and_medium():
    """Stream skips DROP events end-to-end."""
    agg = Aggregator(AggregatorConfig(medium_min_risk=0.5))

    async def gen():
        yield _evt(EventSource.CHAIN_BLOCK, payload={}, identifier="b1")  # heartbeat
        yield _evt(EventSource.CHAIN_TX, score=0.3)  # below medium → DROP
        yield _evt(
            EventSource.INTEL_GOPLUS,
            score=0.9,
            identifier=f"goplus:8453:{ADDR}",
            payload={"token_address": ADDR},
        )

    out = [t async for t in agg.stream(gen())]
    assert all(t.priority in {Priority.HIGH, Priority.MEDIUM} for t in out)
    assert any(t.priority is Priority.HIGH for t in out)
