"""Pure-function tests for the mempool watcher triage rules."""
from __future__ import annotations

from entity.perception.mempool.mempool_watcher import (
    UNLIMITED_THRESHOLD,
    triage_pending,
)


def _tx(**overrides) -> dict:
    base = {
        "hash": "0xpending",
        "from": "0x1111111111111111111111111111111111111111",
        "to": "0x2222222222222222222222222222222222222222",
        "value": "0x0",
        "input": "0x",
    }
    base.update(overrides)
    return base


def test_quiet_pending_yields_nothing():
    assert triage_pending(_tx(), threats=set()) == []


def test_pending_to_known_threat():
    threat = "0xbad0000000000000000000000000000000000000"
    signals = triage_pending(_tx(to=threat), threats={threat})
    assert any(s.name == "threat_recipient_pending" for s in signals)


def test_pending_unlimited_approval():
    selector = "095ea7b3"
    spender = "0" * 24 + "f" * 40
    amount = f"{UNLIMITED_THRESHOLD:064x}"
    input_hex = "0x" + selector + spender + amount
    signals = triage_pending(_tx(input=input_hex), threats=set())
    assert any(s.name == "unlimited_approval_pending" for s in signals)


def test_pending_bounded_approval_silent():
    selector = "095ea7b3"
    spender = "0" * 24 + "a" * 40
    amount = f"{500:064x}"
    input_hex = "0x" + selector + spender + amount
    signals = triage_pending(_tx(input=input_hex), threats=set())
    assert all(s.name != "unlimited_approval_pending" for s in signals)
