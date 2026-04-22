"""ShillingFilter — every category should fire."""
from __future__ import annotations

import pytest

from entity.action.voice import ShillingFilter, ShillingViolation
from entity.action.voice.shilling_filter import ShillingBlocked


@pytest.mark.parametrize("text, rule", [
    ("buy now",                      "trade_call"),
    ("sell now",                     "trade_call"),
    ("ape in",                       "trade_call"),
    ("the price will reach $5",      "price_prediction"),
    ("going to the moon",            "price_prediction"),
    ("a clear 100x setup",           "multiplier_promise"),
    ("undervalued gem",              "endorsement"),
    ("guaranteed return",            "endorsement"),
    ("you should buy now",           "trade_call"),
    ("$FOO 🚀",                       "ticker_hype"),
])
def test_blocks_known_patterns(text, rule):
    f = ShillingFilter()
    v = f.check(text)
    assert v is not None
    assert v.rule == rule


def test_passes_legitimate_alert_text():
    f = ShillingFilter()
    text = (
        "I observe a honeypot.\n"
        "At address 0xdeadbeef.\n"
        "Holders of the token: do not interact.\n"
        "Severity 87/100. Confidence 0.92."
    )
    assert f.is_clean(text)


def test_assert_clean_raises_on_violation():
    f = ShillingFilter()
    with pytest.raises(ShillingBlocked) as exc_info:
        f.assert_clean("buy now")
    assert isinstance(exc_info.value.violation, ShillingViolation)
    assert exc_info.value.violation.rule == "trade_call"


def test_passes_factual_dollar_reference():
    """We should NOT block factual references like '$5M was drained'."""
    f = ShillingFilter()
    assert f.is_clean("$5M was drained from this contract.")
    assert f.is_clean("Treasury balance is $12,345.")
