"""FastAPI assembly.

`build_app()` wires the three x402 endpoints + agent discovery. Pass it
already-constructed dependencies (Reasoner, MemoryStore, PaymentVerifier)
so the same factory is reusable for tests + production.
"""
from __future__ import annotations

from fastapi import FastAPI

from ..cognition.memory import MemoryStore
from ..cognition.reasoner import Reasoner
from .discovery import default_descriptor
from .endpoints.intel import make_intel_router
from .endpoints.scan import make_scan_router
from .endpoints.simulate import make_simulate_router
from .x402 import PaymentVerifier


def build_app(
    *,
    reasoner: Reasoner,
    memory: MemoryStore,
    payment_verifier: PaymentVerifier,
    treasury_address: str,
) -> FastAPI:
    app = FastAPI(
        title="The Good Entity",
        version="v1.0",
        description=(
            "Three paid x402 endpoints over Base USDC: Elder Sign Threat "
            "Scanner, Threat Intel Feed, Banishing Ritual."
        ),
    )

    app.include_router(make_scan_router(
        reasoner=reasoner, verifier=payment_verifier, recipient=treasury_address,
    ))
    app.include_router(make_intel_router(
        memory=memory, verifier=payment_verifier, recipient=treasury_address,
    ))
    app.include_router(make_simulate_router(
        reasoner=reasoner, verifier=payment_verifier, recipient=treasury_address,
    ))

    @app.get("/agent.json")
    async def agent_descriptor():
        return default_descriptor(recipient_address=treasury_address)

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok"}

    return app
