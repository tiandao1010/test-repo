"""Router decision tree + fallback chain."""
from __future__ import annotations

import pytest

from entity.cognition.brains.base import BrainUnavailable
from entity.cognition.brains.stub import StubBrain, make_failing_stub
from entity.cognition.router import Router, RouterPolicy
from entity.cognition.types import Complexity, Sensitivity, Task, TaskType, Urgency


def _task(t: TaskType) -> Task:
    return Task(
        type=t,
        sensitivity=Sensitivity.PUBLIC,
        urgency=Urgency.REALTIME,
        complexity=Complexity.MODERATE,
        subject="addr:0xdead",
        instruction="classify",
    )


def test_route_picks_default_primary():
    sonnet = StubBrain("claude:sonnet")
    haiku = StubBrain("claude:haiku")
    opus = StubBrain("claude:opus")
    router = Router(brains=[sonnet, haiku, opus])

    route = router.route(_task(TaskType.CLASSIFY_THREAT))
    assert route.chain[0].name == "claude:sonnet"


def test_route_picks_opus_for_deep_incident():
    sonnet = StubBrain("claude:sonnet")
    opus = StubBrain("claude:opus")
    router = Router(brains=[sonnet, opus])
    route = router.route(_task(TaskType.DEEP_INCIDENT))
    assert route.chain[0].name == "claude:opus"


def test_route_picks_grok_for_realtime_intel():
    grok = StubBrain("grok:grok-4")
    sonnet = StubBrain("claude:sonnet")
    router = Router(brains=[grok, sonnet])
    route = router.route(_task(TaskType.REALTIME_INTEL))
    assert route.chain[0].name == "grok:grok-4"


def test_route_picks_venice_for_malware_analyze():
    venice = StubBrain("venice:venice-uncensored")
    opus = StubBrain("claude:opus")
    router = Router(brains=[venice, opus])
    route = router.route(_task(TaskType.MALWARE_ANALYZE))
    assert route.chain[0].name == "venice:venice-uncensored"


async def test_dispatch_falls_forward_on_primary_failure():
    primary = make_failing_stub("claude:sonnet")
    secondary = StubBrain("claude:haiku")
    router = Router(brains=[primary, secondary])
    response = await router.dispatch(
        task=_task(TaskType.CLASSIFY_THREAT),
        system="sys",
        user="usr",
    )
    assert response.brain == "claude:haiku"


async def test_dispatch_raises_when_all_brains_fail():
    primary = make_failing_stub("claude:sonnet")
    secondary = make_failing_stub("claude:haiku")
    tertiary = make_failing_stub("claude:opus")
    router = Router(brains=[primary, secondary, tertiary])
    with pytest.raises(BrainUnavailable):
        await router.dispatch(
            task=_task(TaskType.CLASSIFY_THREAT),
            system="sys",
            user="usr",
        )


def test_route_falls_back_to_any_registered_brain_for_unmapped_task():
    """If policy lists no brains we have, return at least one."""
    only = StubBrain("claude:haiku")
    policy = RouterPolicy(routes={TaskType.CLASSIFY_THREAT: ("nonexistent:brain",)})
    router = Router(brains=[only], policy=policy)
    route = router.route(_task(TaskType.CLASSIFY_THREAT))
    assert len(route.chain) == 1
    assert route.chain[0].name == "claude:haiku"
