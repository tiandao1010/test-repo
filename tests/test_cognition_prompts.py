"""Immutable Core hash + prompt assembly."""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from entity.cognition.prompts.loader import (
    CoreHashMismatch,
    PromptLoader,
    assemble_system_prompt,
    default_loader,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_default_loader_passes_hash_check():
    loader = default_loader(REPO_ROOT)
    bundle = loader.load()
    assert bundle.immutable_core.startswith("# THE GOOD ENTITY")
    assert "Five Directives" in bundle.immutable_core
    assert bundle.operational.startswith("# OPERATIONAL LAYER")
    assert len(bundle.core_sha256) == 64


def test_recomputed_hash_matches_lock_file():
    core_path = REPO_ROOT / "prompts" / "immutable_core" / "core_v1_en.md"
    lock_path = REPO_ROOT / "prompts" / "immutable_core" / "core_hash.lock"
    on_disk = hashlib.sha256(core_path.read_bytes()).hexdigest()
    locked = lock_path.read_text(encoding="utf-8").split()[0]
    assert on_disk == locked


def test_tampered_core_raises(tmp_path: Path):
    # Write a core that doesn't match the lock.
    core = tmp_path / "core.md"
    lock = tmp_path / "core.lock"
    op = tmp_path / "op.md"
    core.write_text("tampered content", encoding="utf-8")
    lock.write_text("0" * 64 + "  core.md\n", encoding="utf-8")
    op.write_text("operational", encoding="utf-8")

    loader = PromptLoader(core, lock, op)
    with pytest.raises(CoreHashMismatch):
        loader.load()


def test_assemble_orders_core_then_operational_then_context():
    loader = default_loader(REPO_ROOT)
    bundle = loader.load()
    assembled = assemble_system_prompt(bundle, "scratchpad note")

    core_idx = assembled.index("IMMUTABLE CORE")
    op_idx = assembled.index("OPERATIONAL LAYER")
    ctx_idx = assembled.index("CONTEXT")
    assert core_idx < op_idx < ctx_idx
    assert "scratchpad note" in assembled


def test_assemble_omits_context_when_blank():
    loader = default_loader(REPO_ROOT)
    bundle = loader.load()
    assembled = assemble_system_prompt(bundle, "")
    assert "CONTEXT" not in assembled
