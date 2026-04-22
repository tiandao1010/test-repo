"""Spending guardrail — caps + whitelists."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from entity.safety.guardrail import (
    GuardrailConfig,
    GuardrailReason,
    SpendingGuardrail,
)


def test_negative_amount_refused():
    g = SpendingGuardrail()
    d = g.decide(asset="USDC", amount_usd=-1.0, recipient="0xabc")
    assert not d.allowed
    assert d.reason is GuardrailReason.AMOUNT_NEGATIVE


def test_asset_not_whitelisted_refused():
    g = SpendingGuardrail()
    d = g.decide(asset="DOGE", amount_usd=10.0, recipient="0xabc")
    assert not d.allowed
    assert d.reason is GuardrailReason.ASSET_NOT_WHITELISTED


def test_recipient_whitelist_enforced_when_provided():
    g = SpendingGuardrail(GuardrailConfig(
        recipient_whitelist=frozenset({"0xtreasuryops"})
    ))
    bad = g.decide(asset="USDC", amount_usd=10.0, recipient="0xstranger")
    assert not bad.allowed
    assert bad.reason is GuardrailReason.RECIPIENT_NOT_WHITELISTED

    good = g.decide(asset="USDC", amount_usd=10.0, recipient="0xtreasuryops")
    assert good.allowed


def test_single_tx_cap_enforced():
    g = SpendingGuardrail(GuardrailConfig(single_tx_cap_usd=500))
    over = g.decide(asset="USDC", amount_usd=500.01, recipient="0xabc")
    assert not over.allowed
    assert over.reason is GuardrailReason.SINGLE_TX_OVER_CAP


def test_daily_cap_enforced_across_multiple_txs():
    g = SpendingGuardrail(GuardrailConfig(
        single_tx_cap_usd=500, daily_cap_usd=1000, monthly_cap_usd=20000
    ))
    now = datetime(2026, 4, 22, 10, 0, tzinfo=UTC)
    g.record(400, when=now - timedelta(hours=1))
    g.record(400, when=now - timedelta(minutes=30))
    over = g.decide(asset="USDC", amount_usd=300, recipient="0xabc", now=now)
    assert not over.allowed
    assert over.reason is GuardrailReason.DAILY_OVER_CAP


def test_monthly_cap_enforced():
    g = SpendingGuardrail(GuardrailConfig(
        single_tx_cap_usd=500, daily_cap_usd=20000, monthly_cap_usd=1500
    ))
    now = datetime(2026, 4, 22, 10, 0, tzinfo=UTC)
    g.record(500, when=now - timedelta(days=15))
    g.record(500, when=now - timedelta(days=10))
    g.record(400, when=now - timedelta(days=5))
    over = g.decide(asset="USDC", amount_usd=200, recipient="0xabc", now=now)
    assert not over.allowed
    assert over.reason is GuardrailReason.MONTHLY_OVER_CAP


def test_evicts_stale_spends_beyond_30d():
    g = SpendingGuardrail(GuardrailConfig(monthly_cap_usd=1000))
    now = datetime(2026, 4, 22, tzinfo=UTC)
    g.record(900, when=now - timedelta(days=45))   # ancient — evicted
    g.record(50,  when=now - timedelta(days=2))
    decision = g.decide(asset="USDC", amount_usd=200, recipient="0xabc", now=now)
    assert decision.allowed


def test_happy_path_allows_and_records():
    g = SpendingGuardrail()
    d = g.decide(asset="USDC", amount_usd=100, recipient="0xabc")
    assert d.allowed
    g.record(100)
    assert g.total_spent_24h() == 100
