"""InMemoryStore + StubEmbedder behaviour."""
from __future__ import annotations

import pytest

from entity.cognition.memory import (
    InMemoryStore,
    MemoryRecord,
    RecordKind,
    StubEmbedder,
)


@pytest.fixture
def store() -> InMemoryStore:
    return InMemoryStore(StubEmbedder(dim=128))


async def test_save_assigns_id_and_preserves_fields(store: InMemoryStore):
    record = MemoryRecord(
        kind=RecordKind.THREAT,
        subject="addr:0xdead",
        summary="honeypot demo",
        body="full body text",
        metadata={"severity": 80},
    )
    saved = await store.save(record)
    assert saved.record_id == 1
    assert saved.subject == "addr:0xdead"
    assert saved.metadata["severity"] == 80
    assert len(store) == 1


async def test_top_k_returns_most_similar_first(store: InMemoryStore):
    await store.save(MemoryRecord(
        kind=RecordKind.THREAT, subject="a",
        summary="honeypot token on Base", body="full"))
    await store.save(MemoryRecord(
        kind=RecordKind.THREAT, subject="b",
        summary="phishing approval drained wallet", body="full"))
    await store.save(MemoryRecord(
        kind=RecordKind.PATTERN, subject="c",
        summary="rugpull liquidity removal", body="full"))

    results = await store.top_k_similar("honeypot token Base", k=2)
    assert len(results) == 2
    assert results[0][0].subject == "a"
    assert results[0][1] >= results[1][1]


async def test_kinds_filter_excludes_other_kinds(store: InMemoryStore):
    await store.save(MemoryRecord(
        kind=RecordKind.THREAT, subject="t1",
        summary="honeypot", body=""))
    await store.save(MemoryRecord(
        kind=RecordKind.PATTERN, subject="p1",
        summary="honeypot pattern", body=""))

    results = await store.top_k_similar(
        "honeypot", k=5, kinds=[RecordKind.PATTERN]
    )
    assert len(results) == 1
    assert results[0][0].kind is RecordKind.PATTERN


async def test_top_k_on_empty_store_returns_empty(store: InMemoryStore):
    assert await store.top_k_similar("anything") == []
