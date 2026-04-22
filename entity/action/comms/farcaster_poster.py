"""Farcaster poster (stub).

Spec defers Farcaster integration to "post-launch / Month 2"
(v1.0 §1.6). For Day 4 we ship the *interface* so the dispatcher can
fan out to multiple channels uniformly, plus a `FarcasterStubPoster`
that logs but does not call the network.

When we wire the real Neynar client later, swap `FarcasterStubPoster` for
the real `FarcasterPoster` — same Protocol shape.
"""
from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from ...safety.killswitch import KillSwitchEngaged, KillSwitchFlag
from ...safety.rate_limiter import RateLimiter
from ..voice import FormattedPost, ShillingFilter

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class FarcasterPostResult:
    posted: bool
    detail: str
    cast_hash: str | None = None
    body: str = ""
    posted_at: datetime | None = None


class FarcasterPoster(Protocol):
    async def post(
        self, post: FormattedPost, *, channel_name: str = "farcaster"
    ) -> FarcasterPostResult: ...


class FarcasterStubPoster(FarcasterPoster):
    """Logs the post locally; never hits Neynar."""

    def __init__(
        self,
        *,
        rate_limiter: RateLimiter,
        killswitch: KillSwitchFlag,
        shilling_filter: ShillingFilter | None = None,
        sink: Callable[[FormattedPost, str], Awaitable[None]] | None = None,
    ) -> None:
        self._rate = rate_limiter
        self._flag = killswitch
        self._shilling = shilling_filter or ShillingFilter()
        self._sink = sink

    async def post(
        self, post: FormattedPost, *, channel_name: str = "farcaster"
    ) -> FarcasterPostResult:
        try:
            self._flag.require_active(action=f"farcaster:{channel_name}")
        except KillSwitchEngaged as exc:
            return FarcasterPostResult(False, f"killswitch: {exc}")

        decision = self._rate.decide(channel_name)
        if not decision.allowed:
            return FarcasterPostResult(False, f"rate-limited: {decision.detail}")

        violation = self._shilling.check(post.body)
        if violation is not None:
            return FarcasterPostResult(
                False, f"shilling-filter: {violation.rule}", body=post.body
            )

        if self._sink is not None:
            await self._sink(post, channel_name)
        else:
            log.info("[farcaster-stub] %s", post.body.replace("\n", " | "))

        self._rate.record(channel_name)
        return FarcasterPostResult(
            True, "stub", body=post.body, posted_at=datetime.now(UTC)
        )
