"""Main orchestration loop.

Wires the layers together:

    perception sources --> Aggregator --> Reasoner --> verdict sink

This file is the single most important runtime entry point. Day-4 will
add the action layer (X poster, treasury, x402 endpoints) as a sink that
consumes verdicts from here.

Today the loop is generic in its sinks: pass any async callable.
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterable, Awaitable, Callable

from ..cognition.reasoner import Reasoner
from ..cognition.types import ReasonedVerdict
from ..perception.aggregator import Aggregator, Priority, Triaged
from ..perception.types import PerceptionEvent
from .reasoner_factory import build_default_reasoner  # noqa: F401  re-exported for callers

log = logging.getLogger(__name__)

VerdictSink = Callable[[ReasonedVerdict, Triaged], Awaitable[None]]


class EntityLoop:
    """Async loop binding perception → cognition → sinks."""

    def __init__(
        self,
        aggregator: Aggregator,
        reasoner: Reasoner,
        sinks: list[VerdictSink],
        *,
        min_priority: Priority = Priority.MEDIUM,
    ) -> None:
        self._aggregator = aggregator
        self._reasoner = reasoner
        self._sinks = sinks
        self._min_priority = min_priority

    async def run(self, events: AsyncIterable[PerceptionEvent]) -> None:
        async for triaged in self._aggregator.stream(events):
            if not _meets_priority(triaged, self._min_priority):
                continue
            try:
                verdict = await self._reasoner.reason(triaged)
            except Exception as exc:
                log.error("reasoner failed for subject=%s: %s", triaged.subject, exc)
                continue
            await self._fanout(verdict, triaged)

    async def _fanout(self, verdict: ReasonedVerdict, triaged: Triaged) -> None:
        if not self._sinks:
            return
        await asyncio.gather(
            *(self._safe_call(sink, verdict, triaged) for sink in self._sinks),
            return_exceptions=False,
        )

    @staticmethod
    async def _safe_call(sink: VerdictSink, verdict: ReasonedVerdict, triaged: Triaged) -> None:
        try:
            await sink(verdict, triaged)
        except Exception as exc:
            log.error("sink %s failed: %s", getattr(sink, "__name__", sink), exc)


def _meets_priority(triaged: Triaged, threshold: Priority) -> bool:
    order = {Priority.DROP: 0, Priority.MEDIUM: 1, Priority.HIGH: 2}
    return order[triaged.priority] >= order[threshold]
