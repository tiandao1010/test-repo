"""GET /intel — Threat Intel Feed.

Cost: $0.10 USDC. Returns recent threats Entity has classified, optionally
filtered by `address` or `since`.

Strategy: query the `MemoryStore` for recent records of kind=THREAT.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, Query

from ...cognition.memory import MemoryStore, RecordKind
from ..x402 import (
    PaymentVerification,
    PaymentVerifier,
    require_payment,
    settled_response,
)

router = APIRouter()


def make_intel_router(
    *,
    memory: MemoryStore,
    verifier: PaymentVerifier,
    recipient: str,
) -> APIRouter:
    pay = require_payment(
        asset="USDC", amount_usd=0.10,
        recipient=recipient, verifier=verifier,
    )

    @router.get("/intel")
    async def intel(
        address: str | None = Query(default=None, pattern=r"^0x[0-9a-fA-F]{40}$"),
        limit: int = Query(default=20, ge=1, le=100),
        since_hours: int = Query(default=168, ge=1, le=24 * 30),
        payment: PaymentVerification = Depends(pay),
    ) -> Any:
        cutoff = datetime.now(UTC) - timedelta(hours=since_hours)
        query = address.lower() if address else "recent threats"

        results = await memory.top_k_similar(
            query_text=query, k=limit, kinds=[RecordKind.THREAT]
        )

        items = []
        for record, similarity in results:
            if record.created_at < cutoff:
                continue
            if address and address.lower() not in record.subject.lower():
                continue
            items.append(
                {
                    "id":         record.record_id,
                    "subject":    record.subject,
                    "summary":    record.summary,
                    "metadata":   record.metadata,
                    "created_at": record.created_at.isoformat(),
                    "similarity": similarity,
                }
            )

        return settled_response(
            {"items": items[:limit], "count": len(items[:limit]), "endpoint": "intel"},
            payment,
        )

    return router
