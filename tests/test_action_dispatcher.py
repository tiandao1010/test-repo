"""ActionDispatcher — confidence/severity gates, killswitch, fanout."""
from __future__ import annotations

from datetime import UTC, datetime

from entity.action.comms.farcaster_poster import FarcasterStubPoster
from entity.action.comms.x_poster import XPoster
from entity.action.dispatcher import ActionDispatcher, DispatcherConfig
from entity.cognition.types import ReasonedVerdict, Threat, ThreatClass
from entity.perception.aggregator import Priority, Triaged
from entity.perception.types import EventSource, PerceptionEvent, RiskSignal
from entity.safety.killswitch import KillSwitchFlag
from entity.safety.rate_limiter import RateLimiter


def _verdict(cls=ThreatClass.HONEYPOT, *, severity=80, conf=0.9) -> ReasonedVerdict:
    return ReasonedVerdict(
        threat=Threat(
            threat_class=cls, target="addr:0xdead",
            severity=severity, confidence=conf,
            summary="x", evidence=(), chain_refs=(),
            classified_at=datetime(2026, 4, 22, tzinfo=UTC),
        ),
        brain="claude:opus",
        reasoning="r",
    )


def _triaged() -> Triaged:
    evt = PerceptionEvent(
        source=EventSource.CHAIN_TX,
        observed_at=datetime(2026, 4, 22, tzinfo=UTC),
        identifier="0xtx", payload={"to": "0xdead"},
        signals=(RiskSignal("s", 0.8, "e"),),
    )
    return Triaged(priority=Priority.HIGH, subject="addr:0xdead", events=(evt,))


def _build(flag: KillSwitchFlag | None = None) -> ActionDispatcher:
    flag = flag or KillSwitchFlag()
    rate = RateLimiter()
    return ActionDispatcher(
        x_poster=XPoster(rate_limiter=rate, killswitch=flag, dry_run=True),
        farcaster_poster=FarcasterStubPoster(rate_limiter=rate, killswitch=flag),
        killswitch=flag,
        config=DispatcherConfig(min_confidence_to_post=0.7, min_severity_to_post=60),
    )


async def test_high_confidence_high_severity_posts_to_both_channels():
    d = _build()
    outcome = await d.handle(_verdict(), _triaged())
    assert outcome.skipped_reason is None
    assert outcome.x is not None and outcome.x.posted
    assert outcome.farcaster is not None and outcome.farcaster.posted


async def test_low_confidence_skipped():
    d = _build()
    outcome = await d.handle(_verdict(conf=0.5), _triaged())
    assert outcome.skipped_reason and "confidence" in outcome.skipped_reason
    assert outcome.x is None
    assert outcome.farcaster is None


async def test_low_severity_skipped():
    d = _build()
    outcome = await d.handle(_verdict(severity=20), _triaged())
    assert outcome.skipped_reason and "severity" in outcome.skipped_reason


async def test_silence_class_skipped():
    d = _build()
    outcome = await d.handle(_verdict(cls=ThreatClass.UNKNOWN), _triaged())
    assert outcome.skipped_reason and "silence-class" in outcome.skipped_reason


async def test_killswitch_skips_everything():
    flag = KillSwitchFlag()
    d = _build(flag)
    flag.freeze("test")
    outcome = await d.handle(_verdict(), _triaged())
    assert outcome.skipped_reason and "killswitch" in outcome.skipped_reason
    assert outcome.x is None
    assert outcome.farcaster is None
