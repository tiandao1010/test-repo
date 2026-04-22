"""Embedding clients.

Production uses OpenAI's `text-embedding-3-small` (1536-dim, $0.02 / 1M
tokens). Tests use `StubEmbedder` — deterministic hash-derived vectors,
no network.

If you need to swap to a local model later (e.g. `bge-small-en`), keep
the dim at 1536 or migrate the schema in lockstep.
"""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from typing import Protocol

log = logging.getLogger(__name__)

EMBEDDING_DIM = 1536


class Embedder(Protocol):
    dim: int

    async def embed(self, text: str) -> list[float]: ...


class StubEmbedder(Embedder):
    """Hash-kernel embedding (the "hashing trick").

    For each token, hash to a bucket index and a sign, then sum into the
    output vector. Cosine similarity between two embeddings reflects token
    overlap — good enough for unit tests, not for real retrieval.

    Same text -> identical vector. Texts sharing tokens land closer in
    cosine space than texts that share none."""

    dim: int = EMBEDDING_DIM

    def __init__(self, dim: int = EMBEDDING_DIM) -> None:
        self.dim = dim

    async def embed(self, text: str) -> list[float]:
        out = [0.0] * self.dim
        tokens = _tokenise(text)
        if not tokens:
            return out
        for token in tokens:
            digest = hashlib.sha256(token.encode("utf-8")).digest()
            bucket = int.from_bytes(digest[:4], "big") % self.dim
            sign = 1.0 if (digest[4] & 1) else -1.0
            out[bucket] += sign
        return out


def _tokenise(text: str) -> list[str]:
    return [t for t in text.strip().lower().split() if t]


@dataclass(frozen=True)
class OpenAIEmbedderConfig:
    api_key: str
    model: str = "text-embedding-3-small"


class OpenAIEmbedder(Embedder):
    dim: int = EMBEDDING_DIM

    def __init__(self, config: OpenAIEmbedderConfig) -> None:
        from openai import AsyncOpenAI  # local import — keep test path lean

        self._client = AsyncOpenAI(api_key=config.api_key)
        self._model = config.model

    async def embed(self, text: str) -> list[float]:
        response = await self._client.embeddings.create(
            model=self._model,
            input=text,
        )
        return list(response.data[0].embedding)
