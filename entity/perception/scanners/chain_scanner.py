"""Base chain block scanner.

Polls a Base RPC endpoint, walks new blocks tx-by-tx, and emits
PerceptionEvents only when triage rules find something worth attention.
LLM calls are expensive — most traffic must die here, before cognition.
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

from web3 import AsyncWeb3
from web3.providers import AsyncHTTPProvider

from ..types import EventSource, PerceptionEvent, RiskSignal

log = logging.getLogger(__name__)

# ERC-20 approve(address,uint256) selector
APPROVE_SELECTOR = "0x095ea7b3"
UNLIMITED_THRESHOLD = 1 << 255  # any approve >= this is effectively unbounded


@dataclass
class ScannerConfig:
    rpc_url: str
    poll_interval_s: float = 2.0
    max_blocks_per_poll: int = 20
    large_value_eth: float = 100.0


class BaseChainScanner:
    """Stream PerceptionEvents for each block and interesting tx on Base."""

    def __init__(
        self,
        config: ScannerConfig,
        known_threat_addresses: set[str] | None = None,
    ) -> None:
        self._cfg = config
        self._w3 = AsyncWeb3(AsyncHTTPProvider(config.rpc_url))
        self._threats: set[str] = {a.lower() for a in (known_threat_addresses or set())}
        self._last_seen: int | None = None

    async def stream(self) -> AsyncIterator[PerceptionEvent]:
        self._last_seen = await self._w3.eth.block_number
        log.info("chain_scanner started at block %d", self._last_seen)

        while True:
            try:
                head = await self._w3.eth.block_number
            except Exception as exc:
                log.warning("rpc head read failed: %s", exc)
                await asyncio.sleep(self._cfg.poll_interval_s)
                continue

            assert self._last_seen is not None
            start = self._last_seen + 1
            stop = min(head, start + self._cfg.max_blocks_per_poll - 1)

            for block_num in range(start, stop + 1):
                async for event in self._events_from_block(block_num):
                    yield event
                self._last_seen = block_num

            await asyncio.sleep(self._cfg.poll_interval_s)

    async def _events_from_block(self, block_num: int) -> AsyncIterator[PerceptionEvent]:
        try:
            block = await self._w3.eth.get_block(block_num, full_transactions=True)
        except Exception as exc:
            log.warning("failed to fetch block %d: %s", block_num, exc)
            return

        yield PerceptionEvent.now(
            source=EventSource.CHAIN_BLOCK,
            identifier=str(block_num),
            payload={
                "hash": block["hash"].hex(),
                "tx_count": len(block["transactions"]),
            },
        )

        for tx in block["transactions"]:
            signals = triage_tx(tx, self._threats, self._cfg.large_value_eth)
            if signals:
                yield PerceptionEvent.now(
                    source=EventSource.CHAIN_TX,
                    identifier=_hex(tx["hash"]),
                    payload=_tx_payload(tx),
                    signals=tuple(signals),
                )


def triage_tx(
    tx: dict[str, Any],
    threats: set[str],
    large_value_eth: float,
) -> list[RiskSignal]:
    """Cheap rule-based signals. Pure function — easy to unit-test."""
    signals: list[RiskSignal] = []

    to_addr = (tx.get("to") or "").lower() or None
    from_addr = (tx.get("from") or "").lower() or None

    if to_addr and to_addr in threats:
        signals.append(
            RiskSignal("known_threat_recipient", 0.95, f"to={to_addr} on threat list")
        )
    if from_addr and from_addr in threats:
        signals.append(
            RiskSignal("known_threat_sender", 0.90, f"from={from_addr} on threat list")
        )

    if tx.get("to") is None:
        signals.append(
            RiskSignal("contract_deployment", 0.55, "new contract deployment")
        )

    value_wei = int(tx.get("value", 0) or 0)
    value_eth = value_wei / 1e18
    if value_eth >= large_value_eth:
        signals.append(
            RiskSignal("large_value_transfer", 0.65, f"value={value_eth:.2f} ETH")
        )

    input_hex = _input_hex(tx.get("input"))
    if input_hex.startswith(APPROVE_SELECTOR) and len(input_hex) >= 138:
        try:
            amount = int(input_hex[74:138], 16)
            if amount >= UNLIMITED_THRESHOLD:
                signals.append(
                    RiskSignal(
                        "unlimited_approval",
                        0.60,
                        f"approve(unlimited) to={to_addr or '?'}",
                    )
                )
        except ValueError:
            pass

    return signals


def _tx_payload(tx: dict[str, Any]) -> dict[str, Any]:
    return {
        "from": (tx.get("from") or "").lower() or None,
        "to": (tx.get("to") or "").lower() or None,
        "value_wei": int(tx.get("value", 0) or 0),
        "input_prefix": _input_hex(tx.get("input"))[:10],
        "block_number": tx.get("blockNumber"),
    }


def _hex(v: Any) -> str:
    if isinstance(v, bytes | bytearray):
        return "0x" + v.hex()
    s = str(v)
    return s if s.startswith("0x") else "0x" + s


def _input_hex(v: Any) -> str:
    if v is None:
        return "0x"
    if isinstance(v, bytes | bytearray):
        return "0x" + v.hex()
    return str(v) if str(v).startswith("0x") else "0x" + str(v)
