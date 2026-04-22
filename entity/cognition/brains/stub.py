"""Deterministic stub brain.

Used by tests and the offline demo. Given the same `(system, user)` pair
it returns the same canned response. Optionally configured to fail, so
fallback logic can be exercised.
"""
from __future__ import annotations

import hashlib
from collections.abc import Callable

from ..types import BrainResponse
from .base import BrainClient, BrainError, BrainUnavailable


class StubBrain(BrainClient):
    name: str

    def __init__(
        self,
        name: str = "stub:test",
        *,
        responder: Callable[[str, str], str] | None = None,
        fail_with: BrainError | None = None,
    ) -> None:
        self.name = name
        self._responder = responder or _default_response
        self._fail_with = fail_with
        self.calls: list[tuple[str, str]] = []

    async def complete(
        self,
        system: str,
        user: str,
        *,
        max_tokens: int = 1024,
        temperature: float = 0.2,
    ) -> BrainResponse:
        self.calls.append((system, user))
        if self._fail_with is not None:
            raise self._fail_with
        text = self._responder(system, user)
        return BrainResponse(
            brain=self.name,
            text=text,
            prompt_tokens=_approx_tokens(system) + _approx_tokens(user),
            completion_tokens=_approx_tokens(text),
            cost_usd=0.0,
            latency_ms=1,
        )


def _default_response(system: str, user: str) -> str:
    digest = hashlib.sha256((system + "||" + user).encode()).hexdigest()[:8]
    return (
        '{"threat_class": "unknown", "severity": 50, '
        '"confidence": 0.5, "summary": "stub verdict ' + digest + '", '
        '"evidence": ["stub deterministic response"]}'
    )


def make_failing_stub(name: str = "stub:down") -> StubBrain:
    return StubBrain(name=name, fail_with=BrainUnavailable(f"{name} stubbed offline"))


def _approx_tokens(s: str) -> int:
    # Very rough: chars / 4. We don't ship tiktoken on the test path.
    return max(1, len(s) // 4)
