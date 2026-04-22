"""Treasury tracker — weekly report math."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from entity.action.treasury import (
    StubBankrClient,
    TreasurySnapshot,
    TreasuryTracker,
    WalletTx,
)


async def test_weekly_report_aggregates_inflow_outflow_and_starting_balance():
    end = datetime(2026, 4, 22, tzinfo=UTC)
    start = end - timedelta(days=7)
    txs = [
        WalletTx(timestamp=start + timedelta(days=1), amount_usd=200, asset="USDC"),
        WalletTx(timestamp=start + timedelta(days=2), amount_usd=100, asset="USDC"),
        WalletTx(timestamp=start + timedelta(days=3), amount_usd=-50, asset="USDC"),
        WalletTx(timestamp=start + timedelta(days=4), amount_usd=-25, asset="ETH"),
        # outside the window — must be ignored
        WalletTx(timestamp=start - timedelta(days=2), amount_usd=999, asset="USDC"),
    ]
    client = StubBankrClient(
        balance=TreasurySnapshot(
            captured_at=end, total_usd=1225.0,
            by_asset_usd={"USDC": 1200.0, "ETH": 25.0},
        ),
        txs=txs,
    )
    tracker = TreasuryTracker(client)
    report = await tracker.weekly_report(week_ending=end)

    assert report.ending_balance_usd == 1225.0
    assert report.inflow_usd == 300.0
    assert report.outflow_usd == 75.0
    assert report.inflow_count == 2
    assert report.outflow_count == 2
    # starting = ending - inflow + outflow
    assert report.starting_balance_usd == 1000.0


async def test_snapshot_round_trips_balance():
    end = datetime(2026, 4, 22, tzinfo=UTC)
    client = StubBankrClient(
        balance=TreasurySnapshot(captured_at=end, total_usd=42.0,
                                 by_asset_usd={"USDC": 42.0}),
    )
    tracker = TreasuryTracker(client)
    snap = await tracker.snapshot()
    assert snap.total_usd == 42.0
