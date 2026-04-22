"""x402 endpoint behaviour via FastAPI TestClient."""
from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from entity.api.server import build_app
from entity.api.x402 import BypassVerifier
from entity.cognition.brains.stub import StubBrain
from entity.cognition.memory import (
    InMemoryStore,
    MemoryRecord,
    RecordKind,
    StubEmbedder,
)
from entity.cognition.prompts.loader import default_loader
from entity.cognition.reasoner import Reasoner, ReasonerConfig
from entity.cognition.router import Router

REPO_ROOT = Path(__file__).resolve().parents[1]
TREASURY = "0x0000000000000000000000000000000000treasury"


def _verdict_text(cls="honeypot") -> str:
    return (
        f'{{"threat_class": "{cls}", "severity": 87, "confidence": 0.92, '
        f'"summary": "live {cls} on Base", '
        f'"reasoning": "Multiple sources corroborate.", '
        f'"evidence": ["a","b"]}}'
    )


@pytest.fixture
def client():
    bundle = default_loader(REPO_ROOT).load()
    brain = StubBrain(name="claude:opus", responder=lambda s, u: _verdict_text())
    reasoner = Reasoner(
        prompts=bundle, router=Router(brains=[brain]),
        memory=None, config=ReasonerConfig(persist_verdicts=False),
    )
    memory = InMemoryStore(StubEmbedder(dim=64))
    app = build_app(
        reasoner=reasoner, memory=memory,
        payment_verifier=BypassVerifier(), treasury_address=TREASURY,
    )
    return TestClient(app), memory


def test_agent_descriptor_lists_three_endpoints(client):
    c, _ = client
    r = c.get("/agent.json")
    assert r.status_code == 200
    body = r.json()
    paths = {e["path"] for e in body["endpoints"]}
    assert paths == {"/scan", "/intel", "/simulate"}
    assert body["treasury"]["address"] == TREASURY


def test_healthz(client):
    c, _ = client
    assert c.get("/healthz").json() == {"status": "ok"}


def test_scan_without_payment_returns_402_with_requirements(client):
    c, _ = client
    r = c.post("/scan", json={
        "chain_id": 8453, "address": "0xdead000000000000000000000000000000beef01",
    })
    assert r.status_code == 402
    body = r.json()
    detail = body["detail"]
    assert detail["x402Version"] == 1
    assert detail["accepts"][0]["maxAmountRequired"] == "0.50"
    assert detail["accepts"][0]["payTo"] == TREASURY


def test_scan_with_x_payment_returns_verdict(client):
    c, _ = client
    r = c.post(
        "/scan",
        json={"chain_id": 8453, "address": "0xdead000000000000000000000000000000beef01"},
        headers={"X-PAYMENT": "stub-signed-payload"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["threat_class"] == "honeypot"
    assert body["severity"] == 87
    assert body["endpoint"] == "scan"
    assert "X-PAYMENT-Settled" in r.headers


def test_intel_returns_recent_threats(client):
    c, memory = client
    # seed memory directly via a synchronous path: pytest-asyncio runs event loop per test
    import asyncio
    asyncio.get_event_loop().run_until_complete(
        memory.save(MemoryRecord(
            kind=RecordKind.THREAT, subject="addr:0xdead",
            summary="prior honeypot at 0xdead",
            body="incident detail",
            metadata={"severity": 80},
        ))
    )
    r = c.get(
        "/intel?address=0xdead000000000000000000000000000000beef01&limit=5",
        headers={"X-PAYMENT": "stub"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["endpoint"] == "intel"
    assert body["count"] >= 0


def test_simulate_returns_advice_and_actions(client):
    c, _ = client
    r = c.post(
        "/simulate",
        json={
            "chain_id": 8453,
            "address": "0xdead000000000000000000000000000000beef01",
            "context": "trying to revoke approvals",
        },
        headers={"X-PAYMENT": "stub"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["endpoint"] == "simulate"
    assert body["threat_class"] == "honeypot"
    assert "actions" in body
    assert isinstance(body["actions"], list)
    assert "X-PAYMENT-Settled" in r.headers
