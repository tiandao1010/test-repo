"""Kill switch.

Per Prime Directive IV: when 2/3 keyholders sign a freeze on the Guardian
Safe, the Entity halts all action within thirty seconds. No post, no
on-chain tx, no notification, no memory write — only a single incident
record describing the freeze itself.

Two pieces:
  * `KillSwitchFlag` — in-process flag every action checks before acting.
  * `KillSwitchWatcher` — async loop that polls the Guardian Safe for a
    fresh 2/3 signature and flips the flag.

The on-chain polling logic is delegated to a `SafePoller` Protocol so we
can stub it in tests. Real implementation reads
`getThreshold()` and pending signed transactions from the Safe.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Protocol

log = logging.getLogger(__name__)


@dataclass
class FreezeRecord:
    reason: str
    frozen_at: datetime
    signatures_seen: int = 0


class KillSwitchFlag:
    """In-process freeze flag. Every action layer call MUST consult this.

    `freeze()` is idempotent: re-freezing keeps the original timestamp.
    `unfreeze()` requires an explicit operator action; it's intentionally
    not exposed over the action layer.
    """

    def __init__(self) -> None:
        self._record: FreezeRecord | None = None

    def freeze(self, reason: str, *, signatures: int = 0) -> FreezeRecord:
        if self._record is not None:
            return self._record
        self._record = FreezeRecord(
            reason=reason,
            frozen_at=datetime.now(UTC),
            signatures_seen=signatures,
        )
        log.critical("KILL-SWITCH ENGAGED: %s (sigs=%d)", reason, signatures)
        return self._record

    def unfreeze(self, *, operator_token: str) -> None:
        if not operator_token:
            raise ValueError("unfreeze requires an operator token")
        if self._record is not None:
            log.warning("KILL-SWITCH RELEASED by %s after %s", operator_token, self._record.reason)
        self._record = None

    @property
    def is_frozen(self) -> bool:
        return self._record is not None

    @property
    def record(self) -> FreezeRecord | None:
        return self._record

    def require_active(self, action: str) -> None:
        """Raise `KillSwitchEngaged` if frozen. Call before any side-effect."""
        if self._record is not None:
            raise KillSwitchEngaged(action=action, record=self._record)


class KillSwitchEngaged(RuntimeError):
    def __init__(self, action: str, record: FreezeRecord) -> None:
        super().__init__(f"action {action!r} refused — kill switch frozen ({record.reason})")
        self.action = action
        self.record = record


class SafePoller(Protocol):
    """Adapter to whatever on-chain or web API tells us the Safe state."""

    async def latest_freeze(self) -> tuple[bool, int, str]:
        """Return (is_freeze_signed, signatures_count, freeze_reason)."""
        ...


@dataclass
class KillSwitchWatcher:
    """Polls the Guardian Safe and flips the flag when 2/3 is reached."""

    flag: KillSwitchFlag
    poller: SafePoller
    poll_interval_s: float = 5.0
    confirmations_required: int = 2
    _stop: asyncio.Event = field(default_factory=asyncio.Event)

    async def run(self) -> None:
        log.info(
            "killswitch_watcher running (poll=%ss, threshold=%d sigs)",
            self.poll_interval_s, self.confirmations_required,
        )
        while not self._stop.is_set():
            try:
                signed, sigs, reason = await self.poller.latest_freeze()
                if signed and sigs >= self.confirmations_required and not self.flag.is_frozen:
                    self.flag.freeze(reason or "guardian-safe 2/3 signed", signatures=sigs)
            except Exception as exc:
                log.warning("killswitch poll error: %s", exc)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.poll_interval_s)
            except TimeoutError:
                continue

    def stop(self) -> None:
        self._stop.set()
