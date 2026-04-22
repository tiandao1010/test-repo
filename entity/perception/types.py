"""Shared types for perception-layer events.

Every source (chain, mempool, intel feed) emits a `PerceptionEvent`.
Cognition + aggregator only ever consume this shape.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any


class EventSource(str, Enum):
    CHAIN_BLOCK = "chain_block"
    CHAIN_TX = "chain_tx"
    MEMPOOL = "mempool"
    INTEL_REKT = "intel_rekt"
    INTEL_CVE = "intel_cve"
    INTEL_FORTA = "intel_forta"
    INTEL_GOPLUS = "intel_goplus"
    INTEL_PHALCON = "intel_phalcon"


@dataclass(frozen=True)
class RiskSignal:
    name: str
    score: float  # 0.0 - 1.0
    evidence: str


@dataclass(frozen=True)
class PerceptionEvent:
    source: EventSource
    observed_at: datetime
    identifier: str  # tx hash, block number, CVE ID, etc.
    payload: dict[str, Any]
    signals: tuple[RiskSignal, ...] = field(default_factory=tuple)

    @property
    def max_risk(self) -> float:
        return max((s.score for s in self.signals), default=0.0)

    @classmethod
    def now(cls, **kwargs: Any) -> PerceptionEvent:
        return cls(observed_at=datetime.now(UTC), **kwargs)
