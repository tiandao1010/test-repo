"""Kill switch flag + watcher behaviour."""
from __future__ import annotations

import asyncio

import pytest

from entity.safety.killswitch import (
    KillSwitchEngaged,
    KillSwitchFlag,
    KillSwitchWatcher,
    SafePoller,
)


def test_freeze_then_require_active_raises():
    flag = KillSwitchFlag()
    flag.require_active("post")
    flag.freeze("guardian-2of3", signatures=2)
    with pytest.raises(KillSwitchEngaged):
        flag.require_active("post")
    assert flag.is_frozen
    assert flag.record is not None
    assert flag.record.signatures_seen == 2


def test_freeze_is_idempotent():
    flag = KillSwitchFlag()
    a = flag.freeze("first")
    b = flag.freeze("second")
    assert a is b
    assert flag.record.reason == "first"


def test_unfreeze_requires_operator_token():
    flag = KillSwitchFlag()
    flag.freeze("test")
    with pytest.raises(ValueError):
        flag.unfreeze(operator_token="")
    flag.unfreeze(operator_token="ops:human-on-call")
    assert not flag.is_frozen


class _SequencedPoller(SafePoller):
    def __init__(self, sequence: list[tuple[bool, int, str]]) -> None:
        self._seq = list(sequence)
        self.calls = 0

    async def latest_freeze(self):
        self.calls += 1
        if self._seq:
            return self._seq.pop(0)
        return (False, 0, "")


async def test_watcher_freezes_when_threshold_reached():
    flag = KillSwitchFlag()
    poller = _SequencedPoller([
        (False, 1, ""),                    # not enough sigs
        (True, 2, "guardian:freeze"),      # enough — must trip
    ])
    watcher = KillSwitchWatcher(
        flag=flag, poller=poller,
        poll_interval_s=0.01, confirmations_required=2,
    )
    task = asyncio.create_task(watcher.run())
    # Yield long enough to do at least 2 polls
    await asyncio.sleep(0.05)
    watcher.stop()
    await task

    assert flag.is_frozen
    assert "guardian" in flag.record.reason
    assert flag.record.signatures_seen == 2


async def test_watcher_does_not_thrash_already_frozen_flag():
    flag = KillSwitchFlag()
    flag.freeze("operator-manual", signatures=3)
    poller = _SequencedPoller([(True, 2, "guardian:freeze")] * 5)
    watcher = KillSwitchWatcher(
        flag=flag, poller=poller, poll_interval_s=0.01,
    )
    task = asyncio.create_task(watcher.run())
    await asyncio.sleep(0.03)
    watcher.stop()
    await task

    # Reason MUST stay as the first one set
    assert flag.record.reason == "operator-manual"
    assert flag.record.signatures_seen == 3
