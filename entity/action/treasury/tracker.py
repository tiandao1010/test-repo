"""Treasury tracker.

Reads the Entity wallet via the Bankr Wallet API and builds a weekly
report ready to be rendered through the voice formatter.

The Bankr API surface is provider-defined; we keep our coupling thin
behind `BankrWalletClient` Protocol so tests can stub it. Real client
wiring is a Day-4-PM task once we have a key + endpoint.
"""
from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class TreasurySnapshot:
    captured_at: datetime
    total_usd: float
    by_asset_usd: dict[str, float]


@dataclass(frozen=True)
class WalletTx:
    """Minimal tx shape the tracker needs. Map provider data into this."""

    timestamp: datetime
    amount_usd: float        # signed: + inflow, - outflow
    asset: str
    counterparty: str | None = None
    note: str = ""


@dataclass(frozen=True)
class WeeklyReport:
    week_iso: str
    starting_balance_usd: float
    ending_balance_usd: float
    inflow_usd: float
    outflow_usd: float
    inflow_count: int
    outflow_count: int


class BankrWalletClient(Protocol):
    """Minimal surface the tracker needs from a Bankr wallet adapter."""

    async def get_balance(self) -> TreasurySnapshot: ...

    async def get_transactions(
        self, *, since: datetime, until: datetime
    ) -> list[WalletTx]: ...


class StubBankrClient(BankrWalletClient):
    """Test stub — return canned values."""

    def __init__(
        self,
        *,
        balance: TreasurySnapshot | None = None,
        txs: Iterable[WalletTx] = (),
    ) -> None:
        self._balance = balance or TreasurySnapshot(
            captured_at=datetime.now(UTC),
            total_usd=0.0,
            by_asset_usd={},
        )
        self._txs = list(txs)

    async def get_balance(self) -> TreasurySnapshot:
        return self._balance

    async def get_transactions(
        self, *, since: datetime, until: datetime
    ) -> list[WalletTx]:
        return [tx for tx in self._txs if since <= tx.timestamp < until]


class TreasuryTracker:
    def __init__(self, client: BankrWalletClient) -> None:
        self._client = client

    async def snapshot(self) -> TreasurySnapshot:
        return await self._client.get_balance()

    async def weekly_report(self, week_ending: datetime | None = None) -> WeeklyReport:
        end = week_ending or datetime.now(UTC)
        start = end - timedelta(days=7)
        ending = await self._client.get_balance()
        txs = await self._client.get_transactions(since=start, until=end)

        inflow = sum(tx.amount_usd for tx in txs if tx.amount_usd > 0)
        outflow = -sum(tx.amount_usd for tx in txs if tx.amount_usd < 0)
        inflow_count = sum(1 for tx in txs if tx.amount_usd > 0)
        outflow_count = sum(1 for tx in txs if tx.amount_usd < 0)
        starting = ending.total_usd - inflow + outflow

        return WeeklyReport(
            week_iso=start.strftime("%G-W%V"),
            starting_balance_usd=starting,
            ending_balance_usd=ending.total_usd,
            inflow_usd=inflow,
            outflow_usd=outflow,
            inflow_count=inflow_count,
            outflow_count=outflow_count,
        )
