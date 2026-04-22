"""XPoster — dry-run, killswitch, rate-limit, shilling-filter integration."""
from __future__ import annotations

from datetime import UTC, datetime

from entity.action.comms.x_poster import XPoster
from entity.action.voice import Channel, FormattedPost, ShillingFilter
from entity.safety.killswitch import KillSwitchFlag
from entity.safety.rate_limiter import RateLimiter


def _post(body="I observe a honeypot.\nAt address 0xdead.") -> FormattedPost:
    return FormattedPost(channel=Channel.X, body=body)


async def test_dry_run_succeeds_and_records_rate_limit():
    flag = KillSwitchFlag()
    rate = RateLimiter()
    poster = XPoster(rate_limiter=rate, killswitch=flag, dry_run=True)
    result = await poster.post(_post())
    assert result.posted
    assert result.detail == "dry-run"
    assert rate.remaining("x_post") < rate.DEFAULTS["x_post"][0]


async def test_killswitch_blocks_post():
    flag = KillSwitchFlag()
    flag.freeze("test")
    poster = XPoster(rate_limiter=RateLimiter(), killswitch=flag, dry_run=True)
    result = await poster.post(_post())
    assert not result.posted
    assert "killswitch" in result.detail


async def test_rate_limit_blocks_burst():
    flag = KillSwitchFlag()
    rate = RateLimiter(overrides={"x_post": (1, 30.0)})
    poster = XPoster(rate_limiter=rate, killswitch=flag, dry_run=True)
    a = await poster.post(_post(body="I observe a honeypot.\nAt 0xa."))
    b = await poster.post(_post(body="I observe a honeypot.\nAt 0xb."))
    assert a.posted
    assert not b.posted
    assert "rate" in b.detail.lower() or "interval" in b.detail.lower()


async def test_shilling_blocks_post():
    flag = KillSwitchFlag()
    poster = XPoster(
        rate_limiter=RateLimiter(),
        killswitch=flag,
        shilling_filter=ShillingFilter(),
        dry_run=True,
    )
    result = await poster.post(_post(body="buy now, this will moon"))
    assert not result.posted
    assert "shilling" in result.detail


async def test_shadow_sink_used_instead_of_dry_run():
    flag = KillSwitchFlag()
    captured: list[tuple[FormattedPost, str]] = []

    async def sink(post: FormattedPost, channel: str) -> None:
        captured.append((post, channel))

    poster = XPoster(
        rate_limiter=RateLimiter(),
        killswitch=flag,
        dry_run=True,
        shadow_sink=sink,
    )
    result = await poster.post(_post())
    assert result.posted
    assert result.detail == "shadow"
    assert len(captured) == 1


async def test_live_path_uses_injected_factory():
    flag = KillSwitchFlag()

    class FakeClient:
        def __init__(self, cfg):
            self.cfg = cfg
            self.calls: list[str] = []

        def create_tweet(self, text: str):
            self.calls.append(text)

            class R:
                data = {"id": 999}

            return R()

    poster = XPoster(
        config=None,  # factory ignores cfg in this test
        rate_limiter=RateLimiter(),
        killswitch=flag,
        dry_run=False,
        client_factory=lambda cfg: FakeClient(cfg),
    )
    result = await poster.post(_post())
    assert result.posted
    assert result.tweet_id == "999"
    assert isinstance(result.posted_at, datetime) and result.posted_at.tzinfo is UTC
