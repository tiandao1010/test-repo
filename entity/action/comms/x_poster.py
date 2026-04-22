"""X (formerly Twitter) poster.

Wraps `tweepy.Client` so the rest of the codebase doesn't import tweepy.
Three modes:
  * dry_run=True       — never call the API; return what would have been sent.
  * shadow channel set — write to a sink (Telegram, file) instead of X.
  * live               — post to X.

Every call passes through `RateLimiter` and `KillSwitchFlag` first. If
either rejects, no API call happens.
"""
from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from ...safety.killswitch import KillSwitchEngaged, KillSwitchFlag
from ...safety.rate_limiter import RateLimiter
from ..voice import FormattedPost, ShillingFilter

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class XPosterConfig:
    bearer_token: str
    consumer_key: str
    consumer_secret: str
    access_token: str
    access_token_secret: str


@dataclass(frozen=True)
class XPostResult:
    posted: bool
    detail: str
    tweet_id: str | None = None
    body: str = ""
    posted_at: datetime | None = None


ShadowSink = Callable[[FormattedPost, str], Awaitable[None]]


class XPoster:
    def __init__(
        self,
        *,
        config: XPosterConfig | None = None,
        rate_limiter: RateLimiter,
        killswitch: KillSwitchFlag,
        shilling_filter: ShillingFilter | None = None,
        dry_run: bool = True,
        shadow_sink: ShadowSink | None = None,
        client_factory: Callable | None = None,
    ) -> None:
        self._cfg = config
        self._rate = rate_limiter
        self._flag = killswitch
        self._shilling = shilling_filter or ShillingFilter()
        self._dry_run = dry_run
        self._shadow_sink = shadow_sink
        self._client = None
        self._client_factory = client_factory

    async def post(self, post: FormattedPost, *, channel_name: str = "x_post") -> XPostResult:
        try:
            self._flag.require_active(action=f"x_post:{channel_name}")
        except KillSwitchEngaged as exc:
            return XPostResult(False, f"killswitch: {exc}")

        decision = self._rate.decide(channel_name)
        if not decision.allowed:
            return XPostResult(
                False,
                f"rate-limited ({decision.reason.value}): {decision.detail}",
            )

        violation = self._shilling.check(post.body)
        if violation is not None:
            return XPostResult(
                False,
                f"shilling-filter: rule={violation.rule}, match={violation.matched_text!r}",
            )

        if self._shadow_sink is not None:
            await self._shadow_sink(post, channel_name)
            self._rate.record(channel_name)
            return XPostResult(True, "shadow", body=post.body, posted_at=datetime.now(UTC))

        # Live path requires either a real config OR an injected client_factory.
        # Anything less falls back to dry-run.
        can_go_live = (self._cfg is not None) or (self._client_factory is not None)
        if self._dry_run or not can_go_live:
            log.info("[dry-run x] %s", post.body.replace("\n", " | "))
            self._rate.record(channel_name)
            return XPostResult(True, "dry-run", body=post.body, posted_at=datetime.now(UTC))

        client = self._ensure_client()
        try:
            response = client.create_tweet(text=post.body)
        except Exception as exc:
            log.warning("x post failed: %s", exc)
            return XPostResult(False, f"transport: {exc}", body=post.body)

        tweet_id = _extract_tweet_id(response)
        self._rate.record(channel_name)
        return XPostResult(True, "live", tweet_id=tweet_id, body=post.body,
                           posted_at=datetime.now(UTC))

    def _ensure_client(self):
        if self._client is not None:
            return self._client
        if self._client_factory is not None:
            self._client = self._client_factory(self._cfg)
            return self._client
        # late import — keep tests off tweepy
        import tweepy
        assert self._cfg is not None
        self._client = tweepy.Client(
            bearer_token=self._cfg.bearer_token,
            consumer_key=self._cfg.consumer_key,
            consumer_secret=self._cfg.consumer_secret,
            access_token=self._cfg.access_token,
            access_token_secret=self._cfg.access_token_secret,
        )
        return self._client


def _extract_tweet_id(response) -> str | None:
    data = getattr(response, "data", None)
    if isinstance(data, dict):
        return str(data.get("id")) if data.get("id") is not None else None
    return None
