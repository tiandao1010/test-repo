"""Pure-function tests for the chain-scanner triage rules.

No RPC calls, no network. We feed synthetic tx dicts directly.
"""
from __future__ import annotations

from entity.perception.scanners.chain_scanner import (
    UNLIMITED_THRESHOLD,
    triage_tx,
)


def _tx(**overrides) -> dict:
    base = {
        "from": "0x1111111111111111111111111111111111111111",
        "to": "0x2222222222222222222222222222222222222222",
        "value": 0,
        "input": "0x",
    }
    base.update(overrides)
    return base


def test_quiet_tx_yields_no_signals():
    assert triage_tx(_tx(), threats=set(), large_value_eth=100.0) == []


def test_known_threat_recipient_fires_high():
    threat = "0xbad0000000000000000000000000000000000000"
    signals = triage_tx(_tx(to=threat), threats={threat}, large_value_eth=100.0)
    names = [s.name for s in signals]
    assert "known_threat_recipient" in names
    assert any(s.score >= 0.9 for s in signals)


def test_known_threat_sender_fires_high():
    threat = "0xbad0000000000000000000000000000000000000"
    signals = triage_tx(_tx(**{"from": threat}), threats={threat}, large_value_eth=100.0)
    names = [s.name for s in signals]
    assert "known_threat_sender" in names


def test_contract_deployment_detected():
    signals = triage_tx(_tx(to=None), threats=set(), large_value_eth=100.0)
    assert any(s.name == "contract_deployment" for s in signals)


def test_large_value_transfer_above_threshold():
    signals = triage_tx(
        _tx(value=int(150 * 1e18)),
        threats=set(),
        large_value_eth=100.0,
    )
    assert any(s.name == "large_value_transfer" for s in signals)


def test_large_value_below_threshold_silent():
    signals = triage_tx(
        _tx(value=int(50 * 1e18)),
        threats=set(),
        large_value_eth=100.0,
    )
    assert all(s.name != "large_value_transfer" for s in signals)


def test_unlimited_approval_pattern():
    # selector + 32-byte spender + 32-byte amount (all 1s)
    selector = "095ea7b3"
    spender = "0" * 24 + "f" * 40
    amount = f"{UNLIMITED_THRESHOLD:064x}"
    input_hex = "0x" + selector + spender + amount

    signals = triage_tx(
        _tx(input=input_hex),
        threats=set(),
        large_value_eth=100.0,
    )
    assert any(s.name == "unlimited_approval" for s in signals)


def test_bounded_approval_silent():
    selector = "095ea7b3"
    spender = "0" * 24 + "a" * 40
    amount = f"{1000:064x}"
    input_hex = "0x" + selector + spender + amount

    signals = triage_tx(
        _tx(input=input_hex),
        threats=set(),
        large_value_eth=100.0,
    )
    assert all(s.name != "unlimited_approval" for s in signals)
