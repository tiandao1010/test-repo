"""Rate limiter — sliding window per channel.

Per v1.0 §3.4:
    X posts        ≤ 20 / day
    X replies      ≤ 50 / day
    Farcaster      ≤ 30 / day
plus a `min_interval_s` between consecutive sends per channel.

The limiter is purely defensive: even if the action layer goes haywire,
it cannot exceed these caps. Posters MUST `acquire()` before sending and
`record()` after a successful send.
"""
from __future__ import annotations

import logging
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum

log = logging.getLogger(__name__)


class RateLimiterReason(str, Enum):
    OK = "ok"
    DAILY_CAP_REACHED = "daily_cap_reached"
    INTERVAL_TOO_SHORT = "interval_too_short"


@dataclass(frozen=True)
class RateLimiterDecision:
    allowed: bool
    reason: RateLimiterReason
    detail: str = ""


@dataclass
class _ChannelConfig:
    daily_cap: int
    min_interval_s: float


@dataclass
class _ChannelState:
    sends: deque[datetime] = field(default_factory=deque)
    last_send: datetime | None = None


class RateLimiter:
    """Multi-channel sliding-window limiter.

    Standard channel names: ``"x_post"``, ``"x_reply"``, ``"farcaster"``.
    Posters can register additional channels via `register()`.
    """

    DEFAULTS = {
        "x_post":     (20, 30.0),
        "x_reply":    (50, 15.0),
        "farcaster":  (30, 15.0),
    }

    def __init__(self, overrides: dict[str, tuple[int, float]] | None = None) -> None:
        self._cfg: dict[str, _ChannelConfig] = {}
        self._state: dict[str, _ChannelState] = {}
        for name, (cap, interval) in (overrides or self.DEFAULTS).items():
            self.register(name, daily_cap=cap, min_interval_s=interval)
        # ensure all standard channels exist even if overrides skipped some
        for name, (cap, interval) in self.DEFAULTS.items():
            self._cfg.setdefault(name, _ChannelConfig(cap, interval))
            self._state.setdefault(name, _ChannelState())

    def register(self, channel: str, *, daily_cap: int, min_interval_s: float) -> None:
        self._cfg[channel] = _ChannelConfig(daily_cap, min_interval_s)
        self._state[channel] = _ChannelState()

    def decide(self, channel: str, now: datetime | None = None) -> RateLimiterDecision:
        now = now or datetime.now(UTC)
        cfg = self._cfg.get(channel)
        state = self._state.get(channel)
        if cfg is None or state is None:
            return RateLimiterDecision(False, RateLimiterReason.DAILY_CAP_REACHED,
                                       f"unknown channel {channel}")

        self._evict(state, now)

        if state.last_send is not None:
            since = (now - state.last_send).total_seconds()
            if since < cfg.min_interval_s:
                return RateLimiterDecision(
                    False, RateLimiterReason.INTERVAL_TOO_SHORT,
                    f"only {since:.1f}s since last send (needs {cfg.min_interval_s}s)",
                )

        if len(state.sends) >= cfg.daily_cap:
            return RateLimiterDecision(
                False, RateLimiterReason.DAILY_CAP_REACHED,
                f"{len(state.sends)}/{cfg.daily_cap} in last 24h",
            )

        return RateLimiterDecision(True, RateLimiterReason.OK)

    def record(self, channel: str, when: datetime | None = None) -> None:
        when = when or datetime.now(UTC)
        state = self._state.setdefault(channel, _ChannelState())
        state.sends.append(when)
        state.last_send = when

    def remaining(self, channel: str, now: datetime | None = None) -> int:
        cfg = self._cfg.get(channel)
        state = self._state.get(channel)
        if cfg is None or state is None:
            return 0
        self._evict(state, now or datetime.now(UTC))
        return max(0, cfg.daily_cap - len(state.sends))

    @staticmethod
    def _evict(state: _ChannelState, now: datetime) -> None:
        cutoff = now - timedelta(hours=24)
        while state.sends and state.sends[0] < cutoff:
            state.sends.popleft()
