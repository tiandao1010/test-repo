"""x402 payment gating.

x402 is HTTP-native micropayment, originally proposed for AI-agent
billing. The contract from the server's perspective:

  1. Client requests a paid endpoint with no `X-PAYMENT` header.
  2. Server replies HTTP 402 + a JSON `paymentRequirements` body
     describing what to pay (asset, amount, recipient, nonce, expiry).
  3. Client signs + broadcasts the payment, then re-sends the same
     request with `X-PAYMENT: <base64-signed-payload>`.
  4. Server verifies the payment, settles, runs the endpoint, and
     responds with the result + `X-PAYMENT-Settled: <amount>`.

For Day 4 we ship steps 1-2 + an `X-PAYMENT` *acceptance* hook the
verifier delegates to. Real settlement (step 3-4) plugs in a Day-4-PM
wallet; tests bypass with `BypassVerifier`.
"""
from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol
from uuid import uuid4

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class PaymentRequirement:
    asset: str          # "USDC"
    amount_usd: float   # 0.10, 0.50, 2.00
    recipient: str      # Entity treasury address
    chain: str = "base"
    nonce: str = ""
    expires_at: datetime | None = None

    def to_payload(self) -> dict:
        return {
            "x402Version": 1,
            "accepts": [
                {
                    "scheme": "exact",
                    "network": self.chain,
                    "asset": self.asset,
                    "maxAmountRequired": f"{self.amount_usd:.2f}",
                    "payTo": self.recipient,
                    "nonce": self.nonce,
                    "expiresAt": (self.expires_at.isoformat()
                                  if self.expires_at else None),
                }
            ],
        }


@dataclass(frozen=True)
class PaymentVerification:
    accepted: bool
    settled_usd: float
    detail: str = ""


class PaymentVerifier(Protocol):
    async def verify(
        self, requirement: PaymentRequirement, signed_header: str, request: Request
    ) -> PaymentVerification: ...


class BypassVerifier(PaymentVerifier):
    """Always accept. Used in tests + offline demos. NEVER in production."""

    async def verify(
        self,
        requirement: PaymentRequirement,
        signed_header: str,
        request: Request,
    ) -> PaymentVerification:
        return PaymentVerification(True, requirement.amount_usd, "bypass-verifier")


def _new_nonce() -> str:
    return uuid4().hex


def require_payment(
    *,
    asset: str,
    amount_usd: float,
    recipient: str,
    verifier: PaymentVerifier,
    chain: str = "base",
    expires_in_s: int = 300,
) -> Callable[[Request], Awaitable[PaymentVerification]]:
    """FastAPI dependency factory. Use as a `Depends()` in endpoint signatures."""

    async def dep(request: Request) -> PaymentVerification:
        signed = request.headers.get("X-PAYMENT") or request.headers.get("x-payment")
        requirement = PaymentRequirement(
            asset=asset,
            amount_usd=amount_usd,
            recipient=recipient,
            chain=chain,
            nonce=_new_nonce(),
            expires_at=datetime.now(UTC) + timedelta(seconds=expires_in_s),
        )

        if not signed:
            # 402 with payment requirement is the *intended* response — wrap
            # in HTTPException so FastAPI's response model machinery doesn't
            # mis-encode it.
            raise HTTPException(
                status_code=402,
                detail=requirement.to_payload(),
            )

        verification = await verifier.verify(requirement, signed, request)
        if not verification.accepted:
            raise HTTPException(
                status_code=402,
                detail={
                    **requirement.to_payload(),
                    "reason": verification.detail,
                },
            )
        return verification

    return dep


def settled_response(
    body: dict, verification: PaymentVerification
) -> JSONResponse:
    return JSONResponse(
        content=body,
        headers={"X-PAYMENT-Settled": f"{verification.settled_usd:.4f}"},
    )
