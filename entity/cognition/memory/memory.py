"""Memory store.

Two backends, same interface:

  * `InMemoryStore`  — list + cosine in pure Python. Tests + offline demo.
  * `PostgresStore`  — asyncpg + pgvector. Production.

Schema lives in `schema.sql`. Apply once on a fresh DB:

    psql $POSTGRES_DSN -f entity/cognition/memory/schema.sql
"""
from __future__ import annotations

import json
import logging
import math
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Protocol

from .embeddings import Embedder

log = logging.getLogger(__name__)


class RecordKind(str, Enum):
    THREAT = "threat"
    INCIDENT = "incident"
    PATTERN = "pattern"
    REFLECTION = "reflection"
    ORACLE_INTEL = "oracle_intel"


@dataclass(frozen=True)
class MemoryRecord:
    kind: RecordKind
    subject: str
    summary: str
    body: str
    metadata: dict[str, Any] = field(default_factory=dict)
    record_id: int | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))


class MemoryStore(Protocol):
    embedder: Embedder

    async def save(self, record: MemoryRecord) -> MemoryRecord: ...

    async def top_k_similar(
        self,
        query_text: str,
        k: int = 5,
        *,
        kinds: Sequence[RecordKind] | None = None,
    ) -> list[tuple[MemoryRecord, float]]:
        """Return top-k records by cosine similarity, with similarity score in [-1, 1]."""
        ...


class InMemoryStore(MemoryStore):
    embedder: Embedder

    def __init__(self, embedder: Embedder) -> None:
        self.embedder = embedder
        self._rows: list[tuple[MemoryRecord, list[float]]] = []
        self._next_id = 1

    async def save(self, record: MemoryRecord) -> MemoryRecord:
        embedding = await self.embedder.embed(_embedding_text(record))
        stored = MemoryRecord(
            kind=record.kind,
            subject=record.subject,
            summary=record.summary,
            body=record.body,
            metadata=dict(record.metadata),
            record_id=self._next_id,
            created_at=record.created_at,
        )
        self._rows.append((stored, embedding))
        self._next_id += 1
        return stored

    async def top_k_similar(
        self,
        query_text: str,
        k: int = 5,
        *,
        kinds: Sequence[RecordKind] | None = None,
    ) -> list[tuple[MemoryRecord, float]]:
        if not self._rows:
            return []
        q = await self.embedder.embed(query_text)
        kind_filter = set(kinds) if kinds else None
        scored: list[tuple[MemoryRecord, float]] = []
        for record, vec in self._rows:
            if kind_filter is not None and record.kind not in kind_filter:
                continue
            scored.append((record, _cosine(q, vec)))
        scored.sort(key=lambda pair: pair[1], reverse=True)
        return scored[:k]

    def __len__(self) -> int:
        return len(self._rows)


@dataclass(frozen=True)
class PostgresConfig:
    dsn: str
    table: str = "memory_records"


class PostgresStore(MemoryStore):
    """Async pgvector-backed store. Run schema.sql once before use."""

    embedder: Embedder

    def __init__(self, config: PostgresConfig, embedder: Embedder) -> None:
        self._cfg = config
        self.embedder = embedder
        self._pool = None  # asyncpg.Pool, lazily created

    async def _ensure_pool(self):
        if self._pool is None:
            import asyncpg  # local import — only on the prod path
            from pgvector.asyncpg import register_vector

            self._pool = await asyncpg.create_pool(
                self._cfg.dsn,
                init=register_vector,
                min_size=1,
                max_size=4,
            )
        return self._pool

    async def save(self, record: MemoryRecord) -> MemoryRecord:
        pool = await self._ensure_pool()
        embedding = await self.embedder.embed(_embedding_text(record))
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                f"""
                INSERT INTO {self._cfg.table}
                    (kind, subject, summary, body, metadata, embedding)
                VALUES ($1, $2, $3, $4, $5::jsonb, $6)
                RETURNING id, created_at
                """,
                record.kind.value,
                record.subject,
                record.summary,
                record.body,
                json.dumps(record.metadata),
                embedding,
            )
        return MemoryRecord(
            kind=record.kind,
            subject=record.subject,
            summary=record.summary,
            body=record.body,
            metadata=dict(record.metadata),
            record_id=row["id"],
            created_at=row["created_at"],
        )

    async def top_k_similar(
        self,
        query_text: str,
        k: int = 5,
        *,
        kinds: Sequence[RecordKind] | None = None,
    ) -> list[tuple[MemoryRecord, float]]:
        pool = await self._ensure_pool()
        q = await self.embedder.embed(query_text)
        kind_clause = ""
        params: list[Any] = [q, k]
        if kinds:
            kind_clause = "WHERE kind = ANY($3::text[])"
            params.append([k.value for k in kinds])
        sql = f"""
            SELECT id, kind, subject, summary, body, metadata, created_at,
                   1 - (embedding <=> $1) AS similarity
              FROM {self._cfg.table}
              {kind_clause}
             ORDER BY embedding <=> $1
             LIMIT $2
        """
        async with pool.acquire() as conn:
            rows = await conn.fetch(sql, *params)
        return [
            (
                MemoryRecord(
                    kind=RecordKind(r["kind"]),
                    subject=r["subject"],
                    summary=r["summary"],
                    body=r["body"],
                    metadata=dict(r["metadata"] or {}),
                    record_id=r["id"],
                    created_at=r["created_at"],
                ),
                float(r["similarity"]),
            )
            for r in rows
        ]


def _embedding_text(record: MemoryRecord) -> str:
    return f"{record.kind.value}: {record.subject}\n{record.summary}\n{record.body}"


def _cosine(a: list[float], b: list[float]) -> float:
    if len(a) != len(b):
        raise ValueError(f"dim mismatch: {len(a)} vs {len(b)}")
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)
