"""Classifier picks the right TaskType for given Triaged inputs."""
from __future__ import annotations

from datetime import UTC, datetime

from entity.cognition.router import classify
from entity.cognition.types import Sensitivity, TaskType
from entity.perception.aggregator import Priority, Triaged
from entity.perception.types import EventSource, PerceptionEvent, RiskSignal

T0 = datetime(2026, 4, 22, tzinfo=UTC)


def _triaged(events, *, priority: Priority = Priority.MEDIUM, subject: str = "addr:0xdead") -> Triaged:
    return Triaged(priority=priority, subject=subject, events=tuple(events))


def _evt(source, *, payload=None, score=0.7) -> PerceptionEvent:
    return PerceptionEvent(
        source=source,
        observed_at=T0,
        identifier="evt-1",
        payload=payload or {},
        signals=(RiskSignal("test", score, "ev"),),
    )


def test_chain_high_priority_routes_to_deep_incident():
    triaged = _triaged(
        [_evt(EventSource.CHAIN_TX, payload={"to": "0xdead"}),
         _evt(EventSource.MEMPOOL,  payload={"to": "0xdead"})],
        priority=Priority.HIGH,
    )
    task = classify(triaged)
    assert task.type is TaskType.DEEP_INCIDENT
    assert task.complexity.value == "deep"


def test_chain_medium_priority_routes_to_classify():
    triaged = _triaged(
        [_evt(EventSource.CHAIN_TX, payload={"to": "0xdead"})],
        priority=Priority.MEDIUM,
    )
    task = classify(triaged)
    assert task.type is TaskType.CLASSIFY_THREAT


def test_intel_rekt_routes_to_venice_uncensored():
    triaged = _triaged(
        [_evt(EventSource.INTEL_REKT, payload={"summary": "post-mortem of an exploit"})]
    )
    task = classify(triaged)
    assert task.type is TaskType.MALWARE_ANALYZE
    assert task.sensitivity is Sensitivity.SENSITIVE


def test_sensitive_payload_routes_to_venice_tee():
    triaged = _triaged(
        [_evt(EventSource.CHAIN_TX,
              payload={"summary": "leaked private key in calldata"})],
        priority=Priority.MEDIUM,
    )
    task = classify(triaged)
    assert task.type is TaskType.SENSITIVE_ANALYZE
    assert task.sensitivity is Sensitivity.CONFIDENTIAL


def test_social_payload_routes_to_grok():
    triaged = _triaged(
        [_evt(EventSource.INTEL_FORTA,
              payload={"description": "trending on x.com about this token"})]
    )
    task = classify(triaged)
    assert task.type is TaskType.REALTIME_INTEL


def test_format_post_hint_overrides():
    triaged = _triaged(
        [_evt(EventSource.CHAIN_TX, payload={"to": "0xdead"})],
        priority=Priority.HIGH,
    )
    task = classify(triaged, hint="format_post")
    assert task.type is TaskType.FORMAT_POST
