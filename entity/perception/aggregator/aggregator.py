"""Aggregator pre-filter.

Merges PerceptionEvents from chain / mempool / intel sources, dedupes
events that point at the same subject (a contract address, a tx hash, a
CVE ID), and assigns a coarse priority before anything reaches cognition.

Rule from the v1.0 spec, section 3.2:
  - >= 2 independent sources agreeing on the same subject  →  HIGH
  - 1 source                                              →  MEDIUM
  - everything else                                       →  DROP

HIGH and MEDIUM go upstream. DROP is logged-only; cognition never sees it.
This is the choke point that keeps LLM cost bounded.
"""
from __future__ import annotations

import logging
from collections.abc import AsyncIterable, AsyncIterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum

from ..types import EventSource, PerceptionEvent

log = logging.getLogger(__name__)


class Priority(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    DROP = "drop"


@dataclass(frozen=True)
class Triaged:
    priority: Priority
    subject: str
    events: tuple[PerceptionEvent, ...]

    @property
    def sources(self) -> set[EventSource]:
        return {e.source for e in self.events}

    @property
    def max_risk(self) -> float:
        return max((e.max_risk for e in self.events), default=0.0)


@dataclass
class AggregatorConfig:
    high_threshold_sources: int = 2
    dedupe_window_s: float = 1800.0  # 30 min
    medium_min_risk: float = 0.50    # solo events below this → DROP


@dataclass
class _Bucket:
    subject: str
    first_seen: datetime
    last_seen: datetime
    events: list[PerceptionEvent] = field(default_factory=list)

    def add(self, event: PerceptionEvent) -> None:
        self.events.append(event)
        if event.observed_at > self.last_seen:
            self.last_seen = event.observed_at

    @property
    def sources(self) -> set[EventSource]:
        return {e.source for e in self.events}


def subject_of(event: PerceptionEvent) -> str | None:
    """Pick a stable key under which independent sources can agree.

    Same address (lowercased), same tx hash, or same intel identifier
    counts as 'agreeing'. CHAIN_BLOCK has no real subject — emitted as
    heartbeat — so it returns None and is never aggregated.
    """
    if event.source == EventSource.CHAIN_BLOCK:
        return None

    if event.source in {EventSource.CHAIN_TX, EventSource.MEMPOOL}:
        to = event.payload.get("to")
        if to:
            return f"addr:{str(to).lower()}"
        return f"tx:{event.identifier.lower()}"

    if event.source == EventSource.INTEL_GOPLUS:
        token = event.payload.get("token_address")
        if token:
            return f"addr:{str(token).lower()}"

    if event.source == EventSource.INTEL_FORTA:
        addrs = event.payload.get("addresses") or []
        if addrs:
            return f"addr:{str(addrs[0]).lower()}"

    if event.source == EventSource.INTEL_PHALCON:
        tx = event.payload.get("tx_hash")
        if tx:
            return f"tx:{str(tx).lower()}"

    return f"intel:{event.source.value}:{event.identifier.lower()}"


class Aggregator:
    """Stateful merger. Use `ingest()` for batch / test, `stream()` for live."""

    def __init__(self, config: AggregatorConfig | None = None) -> None:
        self._cfg = config or AggregatorConfig()
        self._buckets: dict[str, _Bucket] = {}

    def ingest(self, event: PerceptionEvent) -> Triaged | None:
        """Fold one event in. Returns the current triage state for its subject,
        or None if the event has no aggregatable subject (e.g. block heartbeats).
        """
        subject = subject_of(event)
        if subject is None:
            return None

        self._evict_stale(now=event.observed_at)

        bucket = self._buckets.get(subject)
        if bucket is None:
            bucket = _Bucket(
                subject=subject,
                first_seen=event.observed_at,
                last_seen=event.observed_at,
            )
            self._buckets[subject] = bucket
        bucket.add(event)

        return self._triage(bucket)

    async def stream(
        self,
        events: AsyncIterable[PerceptionEvent],
    ) -> AsyncIterator[Triaged]:
        async for event in events:
            triaged = self.ingest(event)
            if triaged is None:
                continue
            if triaged.priority is Priority.DROP:
                continue
            yield triaged

    def _triage(self, bucket: _Bucket) -> Triaged:
        sources = bucket.sources
        max_risk = max((e.max_risk for e in bucket.events), default=0.0)

        if len(sources) >= self._cfg.high_threshold_sources:
            priority = Priority.HIGH
        elif max_risk >= self._cfg.medium_min_risk:
            priority = Priority.MEDIUM
        else:
            priority = Priority.DROP

        return Triaged(
            priority=priority,
            subject=bucket.subject,
            events=tuple(bucket.events),
        )

    def _evict_stale(self, now: datetime) -> None:
        cutoff = now - timedelta(seconds=self._cfg.dedupe_window_s)
        stale = [s for s, b in self._buckets.items() if b.last_seen < cutoff]
        for s in stale:
            del self._buckets[s]

    @property
    def open_subjects(self) -> int:
        return len(self._buckets)


def utcnow() -> datetime:
    return datetime.now(UTC)
