"""Mempool watcher.

Subscribes to pending transactions over websocket (Alchemy or Blocknative).
Pending visibility lets the Entity warn on exploits *before* they mine.
This is pure observation — the Entity never front-runs, never broadcasts
a competing tx. See Prime Directive II (defense only).
"""
from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

import websockets

from ..types import EventSource, PerceptionEvent, RiskSignal

log = logging.getLogger(__name__)

APPROVE_SELECTOR = "0x095ea7b3"
UNLIMITED_THRESHOLD = 1 << 255


@dataclass
class MempoolConfig:
    provider: str  # "alchemy" | "blocknative"
    api_key: str
    watched_addresses: tuple[str, ...] = ()
    reconnect_delay_s: float = 5.0


class MempoolWatcher:
    """Stream PerceptionEvents for suspicious pending transactions."""

    def __init__(
        self,
        config: MempoolConfig,
        known_threat_addresses: set[str] | None = None,
    ) -> None:
        self._cfg = config
        self._threats = {a.lower() for a in (known_threat_addresses or set())}

    async def stream(self) -> AsyncIterator[PerceptionEvent]:
        url = self._ws_url()
        while True:
            try:
                async with websockets.connect(url) as ws:
                    await self._subscribe(ws)
                    async for msg in ws:
                        event = self._parse(msg)
                        if event is not None:
                            yield event
            except Exception as exc:
                log.warning("mempool ws dropped: %s (reconnecting)", exc)
                await asyncio.sleep(self._cfg.reconnect_delay_s)

    def _ws_url(self) -> str:
        if self._cfg.provider == "alchemy":
            return f"wss://base-mainnet.g.alchemy.com/v2/{self._cfg.api_key}"
        if self._cfg.provider == "blocknative":
            return "wss://api.blocknative.com/v0"
        raise ValueError(f"unknown mempool provider: {self._cfg.provider}")

    async def _subscribe(self, ws: Any) -> None:
        if self._cfg.provider == "alchemy":
            await ws.send(
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "eth_subscribe",
                        "params": [
                            "alchemy_pendingTransactions",
                            {"toAddress": list(self._cfg.watched_addresses)},
                        ],
                    }
                )
            )
        else:
            await ws.send(
                json.dumps(
                    {
                        "categoryCode": "initialize",
                        "eventCode": "checkDappId",
                        "dappId": self._cfg.api_key,
                        "blockchain": {"system": "ethereum", "network": "base-mainnet"},
                    }
                )
            )

    def _parse(self, raw: str | bytes) -> PerceptionEvent | None:
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return None

        tx = _extract_tx(data)
        if tx is None:
            return None

        signals = triage_pending(tx, self._threats)
        if not signals:
            return None

        return PerceptionEvent.now(
            source=EventSource.MEMPOOL,
            identifier=str(tx.get("hash") or "pending"),
            payload={
                "from": (tx.get("from") or "").lower() or None,
                "to": (tx.get("to") or "").lower() or None,
                "value_wei": _to_int(tx.get("value", 0)),
                "input_prefix": _input_hex(tx.get("input"))[:10],
            },
            signals=tuple(signals),
        )


def triage_pending(tx: dict[str, Any], threats: set[str]) -> list[RiskSignal]:
    signals: list[RiskSignal] = []
    to_addr = (tx.get("to") or "").lower() or None
    from_addr = (tx.get("from") or "").lower() or None
    input_hex = _input_hex(tx.get("input"))

    if to_addr and to_addr in threats:
        signals.append(RiskSignal("threat_recipient_pending", 0.95, f"to={to_addr}"))
    if from_addr and from_addr in threats:
        signals.append(RiskSignal("threat_sender_pending", 0.90, f"from={from_addr}"))

    if input_hex.startswith(APPROVE_SELECTOR) and len(input_hex) >= 138:
        try:
            amount = int(input_hex[74:138], 16)
            if amount >= UNLIMITED_THRESHOLD:
                signals.append(
                    RiskSignal(
                        "unlimited_approval_pending",
                        0.65,
                        f"approve(unlimited) to={to_addr or '?'}",
                    )
                )
        except ValueError:
            pass

    return signals


def _extract_tx(msg: dict[str, Any]) -> dict[str, Any] | None:
    if "params" in msg and isinstance(msg["params"], dict) and "result" in msg["params"]:
        return msg["params"]["result"]
    if "transaction" in msg:
        return msg["transaction"]
    return None


def _to_int(v: Any) -> int:
    if isinstance(v, int):
        return v
    s = str(v)
    if s.startswith("0x"):
        try:
            return int(s, 16)
        except ValueError:
            return 0
    try:
        return int(s)
    except ValueError:
        return 0


def _input_hex(v: Any) -> str:
    if v is None:
        return "0x"
    if isinstance(v, bytes | bytearray):
        return "0x" + v.hex()
    s = str(v)
    return s if s.startswith("0x") else "0x" + s
