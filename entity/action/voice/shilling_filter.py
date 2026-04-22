"""Shilling filter — defensive content gate.

The Operational Layer forbids price prediction, investment advice, and
any token endorsement. The Reasoner is told this in its system prompt.
This filter is defense-in-depth: it scans the *final* outgoing string
and blocks anything that smells like shilling, no matter where it came
from.

False positives are acceptable — losing a single legitimate alert is
strictly cheaper than emitting a single shill. False negatives (a shill
sneaking through) violate Prime Directive III tone — if you find one,
*add to the blocklist*, do not weaken the patterns.

Patterns are organised so a reader can see *why* each is here.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# 1. Outright trade calls.
_TRADE_CALL = re.compile(
    r"\b(?:buy|sell|long|short|ape\s*in|dca\s*in|exit\s*now|enter\s*now|"
    r"accumulate\s*now|dump\s*now)\b",
    re.IGNORECASE,
)

# 2. Price prediction language.
_PRICE_PREDICTION = re.compile(
    r"\b(?:price\s*(?:will|going\s*to|prediction|target)|"
    r"will\s*(?:reach|hit|moon|pump|dump|rally|skyrocket|explode)|"
    r"(?:to\s+the\s+moon|mooning|moonshot|gonna\s*moon|going\s+parabolic))\b",
    re.IGNORECASE,
)

# 3. Multipliers used as financial promise (10x, 100x, 1000x).
_MULTIPLIER = re.compile(r"\b(?:10|20|50|100|500|1000)x\b", re.IGNORECASE)

# 4. Endorsement / hype vocabulary.
_ENDORSEMENT = re.compile(
    r"\b(?:undervalued\s+gem|next\s+big\s+thing|sure\s+thing|"
    r"easy\s+money|guaranteed\s+(?:profit|return|gain|gains)|"
    r"risk[-\s]?free|can'?t\s+lose|never\s+goes\s+down|"
    r"wealth\s+machine)\b",
    re.IGNORECASE,
)

# 5. Hype emojis adjacent to a $TICKER.
_TICKER_HYPE = re.compile(r"\$[A-Z]{2,10}\s*[\U0001F680\U0001F4A0\U0001F311✨\U0001F525]")

# 6. Investment-advice framing.
_ADVICE_FRAMING = re.compile(
    r"\b(?:i\s+recommend|i'?d\s+recommend|you\s+should\s+(?:buy|sell|hold)|"
    r"you\s+ought\s+to\s+(?:buy|sell)|highly\s+recommend|don'?t\s+miss|"
    r"last\s+chance\s+to\s+(?:buy|sell|enter))\b",
    re.IGNORECASE,
)


PATTERNS: dict[str, re.Pattern[str]] = {
    "trade_call": _TRADE_CALL,
    "price_prediction": _PRICE_PREDICTION,
    "multiplier_promise": _MULTIPLIER,
    "endorsement": _ENDORSEMENT,
    "ticker_hype": _TICKER_HYPE,
    "advice_framing": _ADVICE_FRAMING,
}


@dataclass(frozen=True)
class ShillingViolation:
    rule: str
    matched_text: str
    span: tuple[int, int]


class ShillingFilter:
    """Scans outgoing text. `check()` returns the first violation, if any.

    Use `assert_clean()` at the very last step before sending to a comms
    channel. The filter is intentionally noisy: a violation should be
    treated as a hard refusal, NOT something to negotiate around.
    """

    def __init__(self, extra_patterns: dict[str, re.Pattern[str]] | None = None) -> None:
        self._patterns = dict(PATTERNS)
        if extra_patterns:
            self._patterns.update(extra_patterns)

    def check(self, text: str) -> ShillingViolation | None:
        for rule, pattern in self._patterns.items():
            m = pattern.search(text)
            if m:
                return ShillingViolation(
                    rule=rule, matched_text=m.group(0), span=m.span()
                )
        return None

    def is_clean(self, text: str) -> bool:
        return self.check(text) is None

    def assert_clean(self, text: str) -> None:
        violation = self.check(text)
        if violation is not None:
            raise ShillingBlocked(violation, text)


class ShillingBlocked(RuntimeError):
    def __init__(self, violation: ShillingViolation, text: str) -> None:
        super().__init__(
            f"shilling filter blocked emission: rule={violation.rule!r} "
            f"matched={violation.matched_text!r}"
        )
        self.violation = violation
        self.text = text
