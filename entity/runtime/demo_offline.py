"""Offline end-to-end demo of the Day-3 cognition loop.

No network, no API keys, no Postgres. Three synthetic perception events
flow through the aggregator, hit the reasoner with a deterministic
StubBrain, and produce ReasonedVerdicts printed to stdout.

Run from repo root:

    python -m entity.runtime.demo_offline
"""
from __future__ import annotations

import asyncio
import sys
from collections.abc import AsyncIterator
from datetime import UTC, datetime

from ..cognition.brains.stub import StubBrain
from ..cognition.types import ReasonedVerdict
from ..perception.aggregator import Aggregator, Triaged
from ..perception.types import EventSource, PerceptionEvent, RiskSignal
from .main import EntityLoop
from .reasoner_factory import build_default_reasoner

NOW = datetime.now(UTC)
ADDR = "0xdead000000000000000000000000000000beef01"
PHISH = "0xbad000000000000000000000000000000abcdef1"


def _evt(source, identifier, payload, signals) -> PerceptionEvent:
    return PerceptionEvent(
        source=source,
        observed_at=NOW,
        identifier=identifier,
        payload=payload,
        signals=tuple(signals),
    )


async def synthetic_events() -> AsyncIterator[PerceptionEvent]:
    yield _evt(
        EventSource.CHAIN_TX,
        "0xtx_honeypot",
        {"to": ADDR, "value_wei": 0},
        [RiskSignal("contract_deployment", 0.55, "new contract")],
    )
    yield _evt(
        EventSource.INTEL_GOPLUS,
        f"goplus:8453:{ADDR}",
        {"token_address": ADDR, "token_name": "GoodCoin", "token_symbol": "GOOD"},
        [RiskSignal("goplus:honeypot", 0.95, "is_honeypot=1")],
    )
    yield _evt(
        EventSource.MEMPOOL,
        "0xpending_phish",
        {"to": PHISH, "input_prefix": "0x095ea7b3"},
        [RiskSignal("unlimited_approval_pending", 0.65, "approve(unlimited)")],
    )


async def print_sink(verdict: ReasonedVerdict, triaged: Triaged) -> None:
    t = verdict.threat
    print()
    print("──── verdict ────")
    print(f"  subject     {triaged.subject}")
    print(f"  priority    {triaged.priority.value}  ({len(triaged.events)} events)")
    print(f"  threat      {t.threat_class.value}")
    print(f"  severity    {t.severity}/100")
    print(f"  confidence  {t.confidence:.2f}")
    print(f"  summary     {t.summary}")
    print(f"  brain       {verdict.brain}")


async def amain() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    print("THE GOOD ENTITY — Day-3 offline cognition demo")
    print("(no network, no LLM, no Postgres — StubBrain only)")
    print()

    stub = StubBrain(name="claude:sonnet")  # router default lands here for CLASSIFY_THREAT
    reasoner = build_default_reasoner(brains=[stub])
    aggregator = Aggregator()
    loop = EntityLoop(aggregator=aggregator, reasoner=reasoner, sinks=[print_sink])

    await loop.run(synthetic_events())

    print()
    print("Demo complete.")
    return 0


def main() -> int:
    return asyncio.run(amain())


if __name__ == "__main__":
    sys.exit(main())
