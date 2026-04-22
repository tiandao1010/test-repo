"""Forta public-alerts client.

Forta exposes a GraphQL endpoint at api.forta.network/graphql. We poll
recent alerts for chosen chain IDs and emit a PerceptionEvent per alert.
Free tier is generous; an API key (`FORTA_API_KEY`) lifts rate limits.
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime

import httpx

from ..types import EventSource, PerceptionEvent, RiskSignal

log = logging.getLogger(__name__)

FORTA_GRAPHQL = "https://api.forta.network/graphql"

# Forta severity → risk score
SEVERITY_SCORE = {
    "CRITICAL": 0.95,
    "HIGH": 0.80,
    "MEDIUM": 0.55,
    "LOW": 0.30,
    "INFO": 0.10,
    "UNKNOWN": 0.40,
}

ALERTS_QUERY = """
query Alerts($chainId: Int!, $first: Int!) {
  alerts(input: {chainId: $chainId, first: $first}) {
    alerts {
      hash
      name
      severity
      description
      protocol
      addresses
      createdAt
    }
  }
}
""".strip()


@dataclass
class FortaConfig:
    chain_ids: tuple[int, ...] = (8453,)  # Base mainnet
    api_key: str | None = None
    poll_interval_s: float = 60.0
    page_size: int = 50


class FortaClient:
    def __init__(
        self,
        config: FortaConfig | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._cfg = config or FortaConfig()
        self._http = http_client or httpx.AsyncClient(timeout=30.0)
        self._seen: set[str] = set()

    async def stream(self) -> AsyncIterator[PerceptionEvent]:
        while True:
            for chain_id in self._cfg.chain_ids:
                try:
                    async for event in self._poll(chain_id):
                        yield event
                except Exception as exc:
                    log.warning("forta poll chain=%d failed: %s", chain_id, exc)
            await asyncio.sleep(self._cfg.poll_interval_s)

    async def _poll(self, chain_id: int) -> AsyncIterator[PerceptionEvent]:
        headers = {"Content-Type": "application/json"}
        if self._cfg.api_key:
            headers["Authorization"] = f"Bearer {self._cfg.api_key}"

        body = {
            "query": ALERTS_QUERY,
            "variables": {"chainId": chain_id, "first": self._cfg.page_size},
        }
        response = await self._http.post(FORTA_GRAPHQL, json=body, headers=headers)
        response.raise_for_status()
        data = response.json()
        alerts = (data.get("data") or {}).get("alerts", {}).get("alerts") or []

        for alert in alerts:
            event = self._normalise(alert, chain_id)
            if event is None:
                continue
            yield event

    def _normalise(self, alert: dict, chain_id: int) -> PerceptionEvent | None:
        alert_hash = alert.get("hash")
        if not alert_hash or alert_hash in self._seen:
            return None
        self._seen.add(alert_hash)

        severity = (alert.get("severity") or "UNKNOWN").upper()
        score = SEVERITY_SCORE.get(severity, SEVERITY_SCORE["UNKNOWN"])

        return PerceptionEvent(
            source=EventSource.INTEL_FORTA,
            observed_at=_parse_iso(alert.get("createdAt")) or datetime.now(UTC),
            identifier=alert_hash,
            payload={
                "chain_id": chain_id,
                "name": alert.get("name", ""),
                "description": (alert.get("description") or "")[:2000],
                "protocol": alert.get("protocol"),
                "addresses": [a.lower() for a in (alert.get("addresses") or [])],
                "severity": severity,
            },
            signals=(
                RiskSignal(
                    name=f"forta:{severity.lower()}",
                    score=score,
                    evidence=alert.get("name", "forta alert"),
                ),
            ),
        )


def _parse_iso(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
