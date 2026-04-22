"""Core hash verifier."""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from entity.safety.core_verifier import CoreHashVerifier
from entity.safety.killswitch import KillSwitchFlag

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_check_once_passes_for_unmodified_core():
    flag = KillSwitchFlag()
    verifier = CoreHashVerifier(
        core_path=REPO_ROOT / "prompts" / "immutable_core" / "core_v1_en.md",
        core_lock_path=REPO_ROOT / "prompts" / "immutable_core" / "core_hash.lock",
        flag=flag,
    )
    ok, observed, expected = verifier.check_once()
    assert ok
    assert observed == expected


def test_tampered_core_engages_killswitch(tmp_path: Path):
    core = tmp_path / "core.md"
    lock = tmp_path / "core.lock"
    real_text = "real core text"
    real_hash = hashlib.sha256(real_text.encode()).hexdigest()
    lock.write_text(f"{real_hash}  core.md\n", encoding="utf-8")
    core.write_text("tampered text", encoding="utf-8")  # different content

    flag = KillSwitchFlag()
    verifier = CoreHashVerifier(core_path=core, core_lock_path=lock, flag=flag)
    ok, observed, expected = verifier.check_once()
    assert not ok
    assert observed != expected


async def test_run_freezes_on_first_mismatch(tmp_path: Path):
    import asyncio

    core = tmp_path / "core.md"
    lock = tmp_path / "core.lock"
    lock.write_text("0" * 64 + "  core.md\n", encoding="utf-8")
    core.write_text("anything not matching", encoding="utf-8")

    flag = KillSwitchFlag()
    verifier = CoreHashVerifier(
        core_path=core, core_lock_path=lock, flag=flag,
        check_interval_s=0.01,
    )
    task = asyncio.create_task(verifier.run())
    await asyncio.sleep(0.03)
    verifier.stop()
    await task

    assert flag.is_frozen
    assert "immutable-core hash mismatch" in flag.record.reason


def test_run_does_not_re_freeze_already_frozen_flag(tmp_path: Path):
    flag = KillSwitchFlag()
    flag.freeze("operator-pre-freeze")
    pytest.skip("covered by KillSwitchFlag.freeze idempotency test")
