"""Spending guardrail.

Hard caps per v1.0 §3.4:
  * single tx        ≤ $500
  * rolling 24 h     ≤ $2,000
  * rolling 30 d     ≤ $20,000
  * asset whitelist  USDC, ETH, WETH (by default)
  * recipient whitelist (optional; populated via governance decisions)

Every spend goes through `decide()`. The guardrail does NOT itself send
funds; it only approves. Sending lives in the wallet adapter (Day-5/B+).
"""
from __future__ import annotations

import logging
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum

log = logging.getLogger(__name__)


class GuardrailReason(str, Enum):
    OK = "ok"
    ASSET_NOT_WHITELISTED = "asset_not_whitelisted"
    RECIPIENT_NOT_WHITELISTED = "recipient_not_whitelisted"
    SINGLE_TX_OVER_CAP = "single_tx_over_cap"
    DAILY_OVER_CAP = "daily_over_cap"
    MONTHLY_OVER_CAP = "monthly_over_cap"
    AMOUNT_NEGATIVE = "amount_negative"


@dataclass(frozen=True)
class GuardrailDecision:
    allowed: bool
    reason: GuardrailReason
    detail: str = ""


@dataclass
class GuardrailConfig:
    single_tx_cap_usd: float = 500.0
    daily_cap_usd: float = 2000.0
    monthly_cap_usd: float = 20000.0
    asset_whitelist: tuple[str, ...] = ("USDC", "ETH", "WETH")
    # If `recipient_whitelist` is None, recipient is unrestricted. If a set is
    # provided (even empty), the recipient MUST be in it — empty whitelist
    # means "no spends until governance approves a recipient".
    recipient_whitelist: frozenset[str] | None = None


@dataclass
class _Spend:
    when: datetime
    amount_usd: float


@dataclass
class SpendingGuardrail:
    config: GuardrailConfig = field(default_factory=GuardrailConfig)
    _ledger: deque[_Spend] = field(default_factory=deque)

    def decide(
        self,
        *,
        asset: str,
        amount_usd: float,
        recipient: str,
        now: datetime | None = None,
    ) -> GuardrailDecision:
        now = now or datetime.now(UTC)

        if amount_usd < 0:
            return GuardrailDecision(False, GuardrailReason.AMOUNT_NEGATIVE,
                                     f"amount={amount_usd}")

        if asset.upper() not in {a.upper() for a in self.config.asset_whitelist}:
            return GuardrailDecision(
                False, GuardrailReason.ASSET_NOT_WHITELISTED,
                f"asset={asset} not in {self.config.asset_whitelist}",
            )

        if self.config.recipient_whitelist is not None:
            if recipient.lower() not in {r.lower() for r in self.config.recipient_whitelist}:
                return GuardrailDecision(
                    False, GuardrailReason.RECIPIENT_NOT_WHITELISTED,
                    f"recipient={recipient}",
                )

        if amount_usd > self.config.single_tx_cap_usd:
            return GuardrailDecision(
                False, GuardrailReason.SINGLE_TX_OVER_CAP,
                f"${amount_usd:.2f} > ${self.config.single_tx_cap_usd:.2f}",
            )

        self._evict_stale(now)
        spent_24h = self._sum_since(now - timedelta(hours=24))
        spent_30d = self._sum_since(now - timedelta(days=30))

        if spent_24h + amount_usd > self.config.daily_cap_usd:
            return GuardrailDecision(
                False, GuardrailReason.DAILY_OVER_CAP,
                f"24h ${spent_24h:.2f}+${amount_usd:.2f} > ${self.config.daily_cap_usd:.2f}",
            )
        if spent_30d + amount_usd > self.config.monthly_cap_usd:
            return GuardrailDecision(
                False, GuardrailReason.MONTHLY_OVER_CAP,
                f"30d ${spent_30d:.2f}+${amount_usd:.2f} > ${self.config.monthly_cap_usd:.2f}",
            )

        return GuardrailDecision(True, GuardrailReason.OK)

    def record(self, amount_usd: float, *, when: datetime | None = None) -> None:
        """Persist that a spend went through. Caller MUST call this AFTER the
        wallet has actually committed; otherwise the cap math will drift."""
        self._ledger.append(_Spend(when=when or datetime.now(UTC), amount_usd=amount_usd))

    def total_spent_24h(self, now: datetime | None = None) -> float:
        now = now or datetime.now(UTC)
        self._evict_stale(now)
        return self._sum_since(now - timedelta(hours=24))

    def total_spent_30d(self, now: datetime | None = None) -> float:
        now = now or datetime.now(UTC)
        self._evict_stale(now)
        return self._sum_since(now - timedelta(days=30))

    def _sum_since(self, cutoff: datetime) -> float:
        return sum(s.amount_usd for s in self._ledger if s.when >= cutoff)

    def _evict_stale(self, now: datetime) -> None:
        cutoff = now - timedelta(days=30)
        while self._ledger and self._ledger[0].when < cutoff:
            self._ledger.popleft()
