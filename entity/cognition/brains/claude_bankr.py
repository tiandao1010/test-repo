"""Claude via Bankr LLM Gateway.

Bankr's Gateway exposes an OpenAI-compatible Chat Completions endpoint
that proxies Claude (Opus / Sonnet / Haiku). Authentication is by API
key. Wallet-based billing happens behind the gateway, so we don't need
to handle x402 here.

Endpoint shape (subject to change — Bankr's docs are the source of truth):
    POST {base_url}/v1/chat/completions
    Authorization: Bearer {api_key}
    Body: {"model": "...", "messages": [...], "max_tokens": N, "temperature": T}
"""
from __future__ import annotations

import time
from dataclasses import dataclass

import httpx

from ..types import BrainResponse
from .base import BrainClient, BrainError, BrainTimeout, BrainUnavailable

DEFAULT_BASE_URL = "https://gateway.bankr.bot"


@dataclass(frozen=True)
class BankrConfig:
    api_key: str
    model: str                       # e.g. "claude-opus-4-7" / "claude-sonnet-4-6" / "claude-haiku-4-5"
    base_url: str = DEFAULT_BASE_URL
    timeout_s: float = 60.0


class ClaudeViaBankr(BrainClient):
    name: str

    def __init__(
        self,
        config: BankrConfig,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._cfg = config
        self.name = f"claude:{_short(config.model)}"
        self._http = http_client or httpx.AsyncClient(timeout=config.timeout_s)

    async def complete(
        self,
        system: str,
        user: str,
        *,
        max_tokens: int = 1024,
        temperature: float = 0.2,
    ) -> BrainResponse:
        url = f"{self._cfg.base_url.rstrip('/')}/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self._cfg.api_key}",
            "Content-Type": "application/json",
        }
        body = {
            "model": self._cfg.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "max_tokens": max_tokens,
            "temperature": temperature,
        }

        t0 = time.perf_counter()
        try:
            response = await self._http.post(url, headers=headers, json=body)
        except httpx.TimeoutException as exc:
            raise BrainTimeout(f"bankr timeout: {exc}") from exc
        except httpx.HTTPError as exc:
            raise BrainUnavailable(f"bankr transport error: {exc}") from exc

        latency_ms = int((time.perf_counter() - t0) * 1000)

        if response.status_code in {401, 403}:
            raise BrainUnavailable(f"bankr auth rejected ({response.status_code})")
        if response.status_code == 429:
            raise BrainUnavailable("bankr rate-limited")
        if response.status_code >= 500:
            raise BrainUnavailable(f"bankr upstream {response.status_code}")
        if response.status_code >= 400:
            raise BrainError(f"bankr request rejected {response.status_code}: {response.text[:200]}")

        data = response.json()
        text = _extract_text(data)
        usage = data.get("usage") or {}

        return BrainResponse(
            brain=self.name,
            text=text,
            prompt_tokens=int(usage.get("prompt_tokens") or 0),
            completion_tokens=int(usage.get("completion_tokens") or 0),
            cost_usd=0.0,  # gateway invoices off-band; we don't trust per-call estimates
            latency_ms=latency_ms,
        )


def _extract_text(data: dict) -> str:
    choices = data.get("choices") or []
    if not choices:
        return ""
    msg = choices[0].get("message") or {}
    content = msg.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(part.get("text", "") for part in content if isinstance(part, dict))
    return ""


def _short(model: str) -> str:
    if "opus" in model:
        return "opus"
    if "sonnet" in model:
        return "sonnet"
    if "haiku" in model:
        return "haiku"
    return model
