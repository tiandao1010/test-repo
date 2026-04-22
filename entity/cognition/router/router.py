"""Brain router.

Given a `Task`, decide which brain answers, with a fallback chain on
failure. The decision tree is intentionally short and table-driven so a
human can audit it at a glance.

Spec mapping (v1.0 §2.3):
    DEEP_INCIDENT       -> opus  (sonnet, then haiku as last resort)
    CLASSIFY_THREAT     -> sonnet (haiku, then opus)
    REALTIME_INTEL      -> grok  (sonnet, then opus)
    MALWARE_ANALYZE     -> venice:uncensored (opus, then sonnet)
    SENSITIVE_ANALYZE   -> venice:tee        (opus, then sonnet)
    FORMAT_POST         -> haiku (sonnet, then opus)
    SUMMARIZE           -> sonnet (haiku, then opus)
"""
from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass

from ..brains.base import BrainClient, BrainError
from ..types import BrainResponse, Task, TaskType

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class BrainRoute:
    """Resolved chain of brains for one task: primary first, then fallbacks."""

    chain: tuple[BrainClient, ...]


@dataclass
class RouterPolicy:
    """Per-task-type chains. Each value is brain *names* in priority order.

    The Router resolves names against a registry it's constructed with, so
    the policy is configuration, not code.
    """

    routes: dict[TaskType, tuple[str, ...]]

    @classmethod
    def default(cls) -> RouterPolicy:
        return cls(
            routes={
                TaskType.DEEP_INCIDENT:    ("claude:opus", "claude:sonnet", "claude:haiku"),
                TaskType.CLASSIFY_THREAT:  ("claude:sonnet", "claude:haiku", "claude:opus"),
                TaskType.REALTIME_INTEL:   ("grok:grok-4", "claude:sonnet", "claude:opus"),
                TaskType.MALWARE_ANALYZE:  ("venice:venice-uncensored", "claude:opus", "claude:sonnet"),
                TaskType.SENSITIVE_ANALYZE: ("venice:venice-tee", "claude:opus", "claude:sonnet"),
                TaskType.FORMAT_POST:      ("claude:haiku", "claude:sonnet", "claude:opus"),
                TaskType.SUMMARIZE:        ("claude:sonnet", "claude:haiku", "claude:opus"),
            }
        )


class Router:
    def __init__(
        self,
        brains: Sequence[BrainClient],
        policy: RouterPolicy | None = None,
    ) -> None:
        self._registry: dict[str, BrainClient] = {b.name: b for b in brains}
        self._policy = policy or RouterPolicy.default()

    def route(self, task: Task) -> BrainRoute:
        names = self._policy.routes.get(task.type, ("claude:sonnet",))
        chain: list[BrainClient] = []
        for name in names:
            brain = self._registry.get(name)
            if brain is not None:
                chain.append(brain)
        if not chain:
            # As a last resort, return any brain we've got.
            chain = list(self._registry.values())[:1]
        if not chain:
            raise RuntimeError("Router has no brains registered")
        return BrainRoute(chain=tuple(chain))

    async def dispatch(
        self,
        task: Task,
        system: str,
        user: str,
        *,
        max_tokens: int = 1024,
        temperature: float = 0.2,
    ) -> BrainResponse:
        """Run the task through the route, falling forward on `BrainError`."""
        route = self.route(task)
        last_exc: BrainError | None = None
        for brain in route.chain:
            try:
                response = await brain.complete(
                    system=system,
                    user=user,
                    max_tokens=max_tokens,
                    temperature=temperature,
                )
                if last_exc is not None:
                    log.warning(
                        "router fell forward to %s for task=%s after %s",
                        brain.name, task.type.value, last_exc,
                    )
                return response
            except BrainError as exc:
                last_exc = exc
                log.warning("brain %s failed for task=%s: %s", brain.name, task.type.value, exc)
                continue

        assert last_exc is not None
        raise last_exc
