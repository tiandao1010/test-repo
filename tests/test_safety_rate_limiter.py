"""Rate limiter — caps + min interval."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from entity.safety.rate_limiter import RateLimiter, RateLimiterReason


def test_first_send_allowed():
    r = RateLimiter()
    assert r.decide("x_post").allowed


def test_min_interval_blocks_burst():
    r = RateLimiter(overrides={"x_post": (20, 30.0)})
    now = datetime(2026, 4, 22, tzinfo=UTC)
    r.record("x_post", when=now)
    decision = r.decide("x_post", now=now + timedelta(seconds=5))
    assert not decision.allowed
    assert decision.reason is RateLimiterReason.INTERVAL_TOO_SHORT


def test_after_min_interval_allowed_again():
    r = RateLimiter(overrides={"x_post": (20, 30.0)})
    now = datetime(2026, 4, 22, tzinfo=UTC)
    r.record("x_post", when=now)
    decision = r.decide("x_post", now=now + timedelta(seconds=31))
    assert decision.allowed


def test_daily_cap_enforced():
    r = RateLimiter(overrides={"x_post": (3, 0.0)})
    now = datetime(2026, 4, 22, tzinfo=UTC)
    r.record("x_post", when=now - timedelta(hours=1))
    r.record("x_post", when=now - timedelta(hours=2))
    r.record("x_post", when=now - timedelta(hours=3))
    decision = r.decide("x_post", now=now)
    assert not decision.allowed
    assert decision.reason is RateLimiterReason.DAILY_CAP_REACHED


def test_evicts_sends_older_than_24h():
    r = RateLimiter(overrides={"x_post": (3, 0.0)})
    now = datetime(2026, 4, 22, tzinfo=UTC)
    r.record("x_post", when=now - timedelta(hours=25))
    r.record("x_post", when=now - timedelta(hours=2))
    assert r.remaining("x_post", now=now) == 2


def test_unknown_channel_refused():
    r = RateLimiter()
    assert not r.decide("imaginary").allowed


def test_register_custom_channel():
    r = RateLimiter()
    r.register("oracle_intel", daily_cap=200, min_interval_s=5)
    assert r.decide("oracle_intel").allowed
    assert r.remaining("oracle_intel") == 200
