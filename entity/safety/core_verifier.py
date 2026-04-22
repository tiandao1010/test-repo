"""Periodic Immutable Core hash verifier.

Re-checks `core_v1_en.md`'s SHA256 against `core_hash.lock` every
`check_interval_s`. On mismatch, freezes the kill switch — the Entity
must not continue with a tampered Core.

Day-1 spec target: 5 minutes (300 s).
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
from dataclasses import dataclass, field
from pathlib import Path

from .killswitch import KillSwitchFlag

log = logging.getLogger(__name__)


@dataclass
class CoreHashVerifier:
    core_path: Path
    core_lock_path: Path
    flag: KillSwitchFlag
    check_interval_s: float = 300.0
    _stop: asyncio.Event = field(default_factory=asyncio.Event)

    async def run(self) -> None:
        log.info("core_verifier running (interval=%ss, file=%s)",
                 self.check_interval_s, self.core_path)
        while not self._stop.is_set():
            ok, observed, expected = self.check_once()
            if not ok and not self.flag.is_frozen:
                self.flag.freeze(
                    f"immutable-core hash mismatch "
                    f"(observed={observed[:12]}…, expected={expected[:12]}…)",
                    signatures=0,
                )
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.check_interval_s)
            except TimeoutError:
                continue

    def check_once(self) -> tuple[bool, str, str]:
        observed = hashlib.sha256(self.core_path.read_bytes()).hexdigest()
        expected = self.core_lock_path.read_text(encoding="utf-8").split()[0]
        return observed == expected, observed, expected

    def stop(self) -> None:
        self._stop.set()
