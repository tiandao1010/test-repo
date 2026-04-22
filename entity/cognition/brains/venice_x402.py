"""Venice via x402 wallet auth.

Venice is uncensored and runs inference inside a TEE — a fit for
analysing raw exploit code or sensitive payloads that other providers
would refuse or log.

x402 is HTTP-native micropayment. The flow is:
  1. POST /v1/chat/completions with no auth.
  2. Venice replies HTTP 402 + a payment requirement (token, amount,
     recipient, nonce).
  3. We sign + broadcast a USDC transfer on Base, then retry the request
     with `X-PAYMENT: <signed_payload>`.
  4. Venice verifies, settles, and returns the completion.

Implementing the wallet-signing path correctly is its own concern (we
need an in-memory hot wallet with strict daily caps — Day-4 work). For
Day 3 we ship the request shape, the 402 handler, and the retry, but
delegate signing to a `PaymentSigner` Protocol so tests can stub it.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Protocol

import httpx

from ..types import BrainResponse
from .base import BrainClient, BrainError, BrainTimeout, BrainUnavailable

DEFAULT_BASE_URL = "https://api.venice.ai"


class PaymentSigner(Protocol):
    """Pluggable signer so the brain doesn't own a hot wallet directly."""

    async def sign(self, payment_required: dict) -> str:
        """Return the value for the X-PAYMENT header."""
        ...


@dataclass(frozen=True)
class VeniceConfig:
    model: str = "venice-uncensored"   # or "venice-tee" for TEE-isolated inference
    base_url: str = DEFAULT_BASE_URL
    timeout_s: float = 90.0
    max_payment_usd: float = 0.50      # Day-3 hard cap; Day-4 guardrail enforces wallet-wide


class VeniceViaX402(BrainClient):
    name: str

    def __init__(
        self,
        config: VeniceConfig,
        signer: PaymentSigner,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._cfg = config
        self._signer = signer
        self.name = f"venice:{config.model}"
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
            response = await self._http.post(url, json=body)
            if response.status_code == 402:
                payment = response.json()
                self._enforce_cap(payment)
                signed = await self._signer.sign(payment)
                response = await self._http.post(
                    url,
                    json=body,
                    headers={"X-PAYMENT": signed},
                )
        except httpx.TimeoutException as exc:
            raise BrainTimeout(f"venice timeout: {exc}") from exc
        except httpx.HTTPError as exc:
            raise BrainUnavailable(f"venice transport error: {exc}") from exc

        latency_ms = int((time.perf_counter() - t0) * 1000)

        if response.status_code in {401, 403}:
            raise BrainUnavailable(f"venice auth rejected ({response.status_code})")
        if response.status_code == 402:
            raise BrainUnavailable("venice still demanding payment after signed retry")
        if response.status_code == 429:
            raise BrainUnavailable("venice rate-limited")
        if response.status_code >= 500:
            raise BrainUnavailable(f"venice upstream {response.status_code}")
        if response.status_code >= 400:
            raise BrainError(f"venice request rejected {response.status_code}: {response.text[:200]}")

        data = response.json()
        choices = data.get("choices") or []
        text = choices[0].get("message", {}).get("content", "") if choices else ""
        usage = data.get("usage") or {}

        return BrainResponse(
            brain=self.name,
            text=text or "",
            prompt_tokens=int(usage.get("prompt_tokens") or 0),
            completion_tokens=int(usage.get("completion_tokens") or 0),
            cost_usd=float(_payment_amount(response.headers)),
            latency_ms=latency_ms,
        )

    def _enforce_cap(self, payment: dict) -> None:
        amount_str = str(
            payment.get("amount")
            or payment.get("maxAmountRequired")
            or "0"
        )
        try:
            amount_usd = float(amount_str)
        except ValueError:
            amount_usd = 0.0
        if amount_usd > self._cfg.max_payment_usd:
            raise BrainError(
                f"venice demanded ${amount_usd:.4f} > cap ${self._cfg.max_payment_usd:.4f}"
            )


def _payment_amount(headers: httpx.Headers) -> float:
    raw = headers.get("X-PAYMENT-Settled") or headers.get("X-Payment-Amount") or "0"
    try:
        return float(raw)
    except ValueError:
        return 0.0
