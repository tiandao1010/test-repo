"""Brain client protocol and shared exceptions.

Every brain (Claude/Bankr, Grok/xAI, Venice/x402, plus the test stub)
implements `BrainClient`. The router treats them all the same.
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..types import BrainResponse


class BrainError(RuntimeError):
    """Generic brain failure. Router falls back on this."""


class BrainTimeout(BrainError):
    """Brain did not respond in time."""


class BrainUnavailable(BrainError):
    """Brain provider is offline / quota exhausted / auth invalid."""


@runtime_checkable
class BrainClient(Protocol):
    """A pluggable LLM endpoint.

    `name` is a stable identifier (e.g. "claude:opus") — used for
    telemetry, fallback ordering, and never appears in public output.
    """

    name: str

    async def complete(
        self,
        system: str,
        user: str,
        *,
        max_tokens: int = 1024,
        temperature: float = 0.2,
    ) -> BrainResponse: ...
