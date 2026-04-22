"""Day-4 offline demo — full pipeline including action layer + safety.

End-to-end:
    perception aggregator
        -> reasoner (StubBrain)
            -> ActionDispatcher
                -> XPoster (dry-run; shilling filter + rate limiter + killswitch)
                -> FarcasterStubPoster

We also exercise the kill switch mid-stream to prove that, once frozen,
no further posts emit.

Run from repo root:

    python -m entity.runtime.demo_day4
"""
from __future__ import annotations

import asyncio
import sys
from collections.abc import AsyncIterator
from datetime import UTC, datetime

from ..action.comms.farcaster_poster import FarcasterStubPoster
from ..action.comms.x_poster import XPoster
from ..action.dispatcher import ActionDispatcher, DispatcherConfig
from ..cognition.brains.stub import StubBrain
from ..perception.aggregator import Aggregator
from ..perception.types import EventSource, PerceptionEvent, RiskSignal
from ..safety.killswitch import KillSwitchFlag
from ..safety.rate_limiter import RateLimiter
from .main import EntityLoop
from .reasoner_factory import build_default_reasoner

NOW = datetime.now(UTC)
ADDR_HONEYPOT = "0xdead000000000000000000000000000000beef01"
ADDR_PHISH = "0xbad000000000000000000000000000000abcdef1"
ADDR_QUIET = "0xfeed00000000000000000000000000000000feed"


def _evt(source, identifier, payload, signals):
    return PerceptionEvent(
        source=source, observed_at=NOW, identifier=identifier,
        payload=payload, signals=tuple(signals),
    )


async def synthetic_events(flag: KillSwitchFlag) -> AsyncIterator[PerceptionEvent]:
    # Subject 1 — honeypot: chain-tx + goplus corroborate -> HIGH
    yield _evt(EventSource.CHAIN_TX, "0xtx_honeypot",
               {"to": ADDR_HONEYPOT},
               [RiskSignal("contract_deployment", 0.55, "deploy")])
    yield _evt(EventSource.INTEL_GOPLUS, f"goplus:8453:{ADDR_HONEYPOT}",
               {"token_address": ADDR_HONEYPOT},
               [RiskSignal("goplus:honeypot", 0.95, "is_honeypot=1")])

    # Subject 2 — phishing approval pattern: mempool + forta -> HIGH
    yield _evt(EventSource.MEMPOOL, "0xpending_phish",
               {"to": ADDR_PHISH, "input_prefix": "0x095ea7b3"},
               [RiskSignal("unlimited_approval_pending", 0.65, "approve(unlimited)")])
    yield _evt(EventSource.INTEL_FORTA, "forta:phishing-cluster",
               {"addresses": [ADDR_PHISH], "severity": "HIGH"},
               [RiskSignal("forta:high", 0.80, "drainer cluster")])

    # Subject 3 — quiet noise: single low-confidence signal -> DROP at aggregator
    yield _evt(EventSource.CHAIN_TX, "0xtx_quiet",
               {"to": ADDR_QUIET},
               [RiskSignal("low", 0.20, "noise")])

    # ── KILL SWITCH ENGAGED here ──
    flag.freeze("demo:keyholder-2of3-override", signatures=2)

    # These two should be silently refused by every poster.
    yield _evt(EventSource.CHAIN_TX, "0xtx_after_freeze",
               {"to": ADDR_HONEYPOT},
               [RiskSignal("known_threat_recipient", 0.95, "frozen")])
    yield _evt(EventSource.INTEL_GOPLUS, f"goplus:8453:{ADDR_HONEYPOT}_again",
               {"token_address": ADDR_HONEYPOT},
               [RiskSignal("goplus:honeypot", 0.95, "is_honeypot=1")])


def _good_response(s: str, u: str) -> str:
    """A clean verdict the dispatcher should be willing to publish."""
    if "phish" in u.lower() or "approval" in u.lower():
        cls = "phishing_approval"
    else:
        cls = "honeypot"
    return (
        f'{{"threat_class": "{cls}", "severity": 85, "confidence": 0.92, '
        f'"summary": "live {cls.replace("_", " ")} on Base", '
        f'"reasoning": "Multiple sources corroborate the {cls} pattern.", '
        f'"evidence": ["multi-source"]}}'
    )


async def amain() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    print("THE GOOD ENTITY — Day-4 offline pipeline demo")
    print("(perception -> cognition -> action layer + safety; no network)")
    print()

    flag = KillSwitchFlag()
    rate = RateLimiter()

    brain = StubBrain(name="claude:sonnet", responder=_good_response)
    reasoner = build_default_reasoner(brains=[brain])

    x_poster = XPoster(rate_limiter=rate, killswitch=flag, dry_run=True)
    farcaster = FarcasterStubPoster(rate_limiter=rate, killswitch=flag)
    dispatcher = ActionDispatcher(
        x_poster=x_poster,
        farcaster_poster=farcaster,
        killswitch=flag,
        config=DispatcherConfig(min_confidence_to_post=0.7, min_severity_to_post=60),
    )

    loop = EntityLoop(
        aggregator=Aggregator(),
        reasoner=reasoner,
        sinks=[dispatcher],
    )
    await loop.run(synthetic_events(flag))

    print()
    print("──── outcomes ────")
    posted = 0
    skipped = 0
    for o in dispatcher.outcomes:
        t = o.verdict.threat
        tag = "SKIP" if o.skipped_reason else "POST"
        if o.skipped_reason:
            skipped += 1
        else:
            posted += 1
        print(f"  [{tag}] {t.threat_class.value:<20} {o.triaged.subject}")
        if o.skipped_reason:
            print(f"         reason: {o.skipped_reason}")
        if o.x:
            print(f"         x:      posted={o.x.posted}  detail={o.x.detail}")

    print()
    print(f"summary: {posted} posted, {skipped} skipped, killswitch={flag.is_frozen}")
    print()
    print("Demo complete.")
    return 0


def main() -> int:
    return asyncio.run(amain())


if __name__ == "__main__":
    sys.exit(main())
