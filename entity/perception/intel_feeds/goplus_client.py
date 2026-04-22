"""GoPlus token-security client.

REST endpoint:
  GET https://api.gopluslabs.io/api/v1/token_security/{chain_id}?contract_addresses=…

Free tier ≈ 500 calls/day. We use it on demand — not a continuous stream,
but on tokens flagged by other layers (e.g. a token that just appeared in
many wallets, or surfaced in a Rekt feed).

Output is shaped as PerceptionEvent so the aggregator treats GoPlus as
just another corroborating source.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime

import httpx

from ..types import EventSource, PerceptionEvent, RiskSignal

log = logging.getLogger(__name__)

GOPLUS_BASE = "https://api.gopluslabs.io/api/v1/token_security"

# Map "1" string returned by GoPlus to (signal_name, score)
DANGER_FLAGS: dict[str, tuple[str, float]] = {
    "is_honeypot": ("honeypot", 0.95),
    "is_blacklisted": ("blacklisted_token", 0.85),
    "is_proxy": ("proxy_token", 0.45),
    "is_mintable": ("mintable_supply", 0.50),
    "can_take_back_ownership": ("ownership_takeback", 0.75),
    "owner_change_balance": ("owner_can_change_balance", 0.80),
    "hidden_owner": ("hidden_owner", 0.85),
    "selfdestruct": ("selfdestructable", 0.80),
    "external_call": ("external_call_during_transfer", 0.40),
    "trading_cooldown": ("trading_cooldown", 0.30),
    "transfer_pausable": ("transfer_pausable", 0.45),
}


@dataclass
class GoPlusConfig:
    api_key: str | None = None
    timeout_s: float = 15.0


class GoPlusClient:
    def __init__(
        self,
        config: GoPlusConfig | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._cfg = config or GoPlusConfig()
        self._http = http_client or httpx.AsyncClient(timeout=self._cfg.timeout_s)

    async def check_token(self, chain_id: int, token_address: str) -> PerceptionEvent | None:
        url = f"{GOPLUS_BASE}/{chain_id}"
        params = {"contract_addresses": token_address.lower()}
        headers = {}
        if self._cfg.api_key:
            headers["Authorization"] = self._cfg.api_key

        try:
            response = await self._http.get(url, params=params, headers=headers)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            log.warning("goplus check failed for %s: %s", token_address, exc)
            return None

        data = response.json()
        result = (data.get("result") or {}).get(token_address.lower())
        if not result:
            return None

        signals: list[RiskSignal] = []
        for flag, (name, score) in DANGER_FLAGS.items():
            if str(result.get(flag, "")).strip() == "1":
                signals.append(
                    RiskSignal(
                        name=f"goplus:{name}",
                        score=score,
                        evidence=f"goplus flag {flag}=1",
                    )
                )

        if not signals:
            return None

        return PerceptionEvent(
            source=EventSource.INTEL_GOPLUS,
            observed_at=datetime.now(UTC),
            identifier=f"goplus:{chain_id}:{token_address.lower()}",
            payload={
                "chain_id": chain_id,
                "token_address": token_address.lower(),
                "token_name": result.get("token_name"),
                "token_symbol": result.get("token_symbol"),
                "raw": result,
            },
            signals=tuple(signals),
        )
