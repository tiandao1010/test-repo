"""Phalcon transaction-simulation client.

Phalcon (BlockSec) exposes a tx-simulation API that returns asset balance
deltas, state changes, and risk findings for a transaction. We feed it
suspicious pending txs from the mempool layer and surface findings as
PerceptionEvents so the aggregator can corroborate before we act.

The free tier API surface has changed over time; this client targets a
stable POST endpoint — tweak `endpoint` in config for paid tiers.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime

import httpx

from ..types import EventSource, PerceptionEvent, RiskSignal

log = logging.getLogger(__name__)

DEFAULT_ENDPOINT = "https://api.phalcon.xyz/v1/simulate"


@dataclass
class PhalconConfig:
    api_key: str | None = None
    endpoint: str = DEFAULT_ENDPOINT
    timeout_s: float = 30.0


class PhalconClient:
    def __init__(
        self,
        config: PhalconConfig | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._cfg = config or PhalconConfig()
        self._http = http_client or httpx.AsyncClient(timeout=self._cfg.timeout_s)

    async def simulate(
        self,
        chain_id: int,
        tx: dict,
    ) -> PerceptionEvent | None:
        headers = {"Content-Type": "application/json"}
        if self._cfg.api_key:
            headers["X-API-Key"] = self._cfg.api_key

        body = {"chainId": chain_id, "tx": tx}

        try:
            response = await self._http.post(self._cfg.endpoint, json=body, headers=headers)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            log.warning("phalcon simulate failed: %s", exc)
            return None

        data = response.json()
        findings = data.get("findings") or []
        signals: list[RiskSignal] = []

        for f in findings:
            severity = (f.get("severity") or "MEDIUM").upper()
            score = {
                "CRITICAL": 0.95,
                "HIGH": 0.80,
                "MEDIUM": 0.55,
                "LOW": 0.25,
            }.get(severity, 0.45)
            signals.append(
                RiskSignal(
                    name=f"phalcon:{f.get('type', 'finding')}",
                    score=score,
                    evidence=str(f.get("message", ""))[:200],
                )
            )

        if not signals:
            return None

        return PerceptionEvent(
            source=EventSource.INTEL_PHALCON,
            observed_at=datetime.now(UTC),
            identifier=f"phalcon:{chain_id}:{tx.get('hash', 'sim')}",
            payload={
                "chain_id": chain_id,
                "tx_hash": tx.get("hash"),
                "balance_changes": data.get("balanceChanges"),
                "state_changes_count": len(data.get("stateChanges") or []),
            },
            signals=tuple(signals),
        )
