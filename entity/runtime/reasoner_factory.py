"""Builders that assemble a Reasoner from configuration.

Kept separate from `main.py` so tests can construct a stubbed Reasoner
without touching production wiring.
"""
from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from ..cognition.brains.base import BrainClient
from ..cognition.memory import InMemoryStore, MemoryStore, StubEmbedder
from ..cognition.prompts.loader import PromptLoader, default_loader
from ..cognition.reasoner import Reasoner, ReasonerConfig
from ..cognition.router import Router, RouterPolicy


def build_default_reasoner(
    brains: Sequence[BrainClient],
    *,
    memory: MemoryStore | None = None,
    prompts_root: Path | None = None,
    config: ReasonerConfig | None = None,
    policy: RouterPolicy | None = None,
) -> Reasoner:
    loader: PromptLoader = default_loader(prompts_root)
    bundle = loader.load()
    router = Router(brains=brains, policy=policy)
    store = memory or InMemoryStore(StubEmbedder())
    return Reasoner(prompts=bundle, router=router, memory=store, config=config)
