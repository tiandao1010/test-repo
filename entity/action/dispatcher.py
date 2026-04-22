"""Action dispatcher — sink for ReasonedVerdicts.

Pipeline per verdict:
    1. killswitch active?     no -> skip everything
    2. confidence threshold   no -> skip (silence is a valid choice)
    3. format                 voice formatter
    4. shilling filter        block + log if violated
    5. fan out                X poster + Farcaster poster (best-effort)
    6. record                 incident log entry

This dispatcher is what `EntityLoop`'s sinks list consumes. Fan-out is
sequential (gather is fine but a posted-then-logged ordering is easier
to reason about during incident review).
"""
from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Protocol

from ..cognition.types import ReasonedVerdict, ThreatClass
from ..perception.aggregator import Triaged
from ..safety.killswitch import KillSwitchFlag
from .comms.farcaster_poster import FarcasterPoster, FarcasterPostResult
from .comms.x_poster import XPoster, XPostResult
from .voice import Channel, render_threat_alert

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class DispatchOutcome:
    verdict: ReasonedVerdict
    triaged: Triaged
    skipped_reason: str | None = None
    x: XPostResult | None = None
    farcaster: FarcasterPostResult | None = None
    decided_at: datetime = field(default_factory=lambda: datetime.now(UTC))


class IncidentLog(Protocol):
    async def write(self, outcome: DispatchOutcome) -> None: ...


class NullIncidentLog(IncidentLog):
    async def write(self, outcome: DispatchOutcome) -> None:
        return None


@dataclass
class DispatcherConfig:
    min_confidence_to_post: float = 0.7
    min_severity_to_post: int = 60
    silence_classes: frozenset[ThreatClass] = frozenset(
        {ThreatClass.BENIGN, ThreatClass.UNKNOWN}
    )


class ActionDispatcher:
    def __init__(
        self,
        *,
        x_poster: XPoster | None,
        farcaster_poster: FarcasterPoster | None,
        killswitch: KillSwitchFlag,
        incident_log: IncidentLog | None = None,
        config: DispatcherConfig | None = None,
    ) -> None:
        self._x = x_poster
        self._fc = farcaster_poster
        self._flag = killswitch
        self._log = incident_log or NullIncidentLog()
        self._cfg = config or DispatcherConfig()
        self.outcomes: list[DispatchOutcome] = []

    async def __call__(self, verdict: ReasonedVerdict, triaged: Triaged) -> None:
        outcome = await self.handle(verdict, triaged)
        self.outcomes.append(outcome)

    async def handle(
        self, verdict: ReasonedVerdict, triaged: Triaged
    ) -> DispatchOutcome:
        if self._flag.is_frozen:
            return await self._record(
                DispatchOutcome(
                    verdict=verdict, triaged=triaged,
                    skipped_reason=f"killswitch: {self._flag.record.reason}",
                )
            )

        threat = verdict.threat
        if threat.threat_class in self._cfg.silence_classes:
            return await self._record(
                DispatchOutcome(
                    verdict=verdict, triaged=triaged,
                    skipped_reason=f"silence-class: {threat.threat_class.value}",
                )
            )
        if threat.confidence < self._cfg.min_confidence_to_post:
            return await self._record(
                DispatchOutcome(
                    verdict=verdict, triaged=triaged,
                    skipped_reason=(
                        f"confidence {threat.confidence:.2f} "
                        f"< {self._cfg.min_confidence_to_post:.2f}"
                    ),
                )
            )
        if threat.severity < self._cfg.min_severity_to_post:
            return await self._record(
                DispatchOutcome(
                    verdict=verdict, triaged=triaged,
                    skipped_reason=(
                        f"severity {threat.severity} < {self._cfg.min_severity_to_post}"
                    ),
                )
            )

        x_post = render_threat_alert(verdict, channel=Channel.X)
        fc_post = render_threat_alert(verdict, channel=Channel.FARCASTER)

        x_result: XPostResult | None = None
        fc_result: FarcasterPostResult | None = None

        if self._x is not None:
            x_result = await self._x.post(x_post)
        if self._fc is not None:
            fc_result = await self._fc.post(fc_post)

        return await self._record(
            DispatchOutcome(
                verdict=verdict, triaged=triaged,
                x=x_result, farcaster=fc_result,
            )
        )

    async def _record(self, outcome: DispatchOutcome) -> DispatchOutcome:
        try:
            await self._log.write(outcome)
        except Exception as exc:
            log.warning("incident log write failed: %s", exc)
        return outcome


def silence_class_set(classes: Iterable[ThreatClass]) -> frozenset[ThreatClass]:
    return frozenset(classes)
