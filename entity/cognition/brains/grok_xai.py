"""Grok via xAI API.

xAI exposes an OpenAI-compatible Chat Completions endpoint at
api.x.ai/v1. Grok's edge over Claude is real-time access to X / Twitter
data — used for breaking-threat intel, whale watching, scam alerts.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

import httpx

from ..types import BrainResponse
from .base import BrainClient, BrainError, BrainTimeout, BrainUnavailable

DEFAULT_BASE_URL = "https://api.x.ai"


@dataclass(frozen=True)
class XaiConfig:
    api_key: str
    model: str = "grok-4"
    base_url: str = DEFAULT_BASE_URL
    timeout_s: float = 60.0


class GrokViaXai(BrainClient):
    name: str

    def __init__(
        self,
        config: XaiConfig,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._cfg = config
        self.name = f"grok:{config.model}"
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
            raise BrainTimeout(f"xai timeout: {exc}") from exc
        except httpx.HTTPError as exc:
            raise BrainUnavailable(f"xai transport error: {exc}") from exc

        latency_ms = int((time.perf_counter() - t0) * 1000)

        if response.status_code in {401, 403}:
            raise BrainUnavailable(f"xai auth rejected ({response.status_code})")
        if response.status_code == 429:
            raise BrainUnavailable("xai rate-limited")
        if response.status_code >= 500:
            raise BrainUnavailable(f"xai upstream {response.status_code}")
        if response.status_code >= 400:
            raise BrainError(f"xai request rejected {response.status_code}: {response.text[:200]}")

        data = response.json()
        choices = data.get("choices") or []
        text = choices[0].get("message", {}).get("content", "") if choices else ""
        usage = data.get("usage") or {}

        return BrainResponse(
            brain=self.name,
            text=text or "",
            prompt_tokens=int(usage.get("prompt_tokens") or 0),
            completion_tokens=int(usage.get("completion_tokens") or 0),
            cost_usd=0.0,
            latency_ms=latency_ms,
        )
