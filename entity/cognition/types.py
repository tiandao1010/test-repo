"""Cognition-layer shared types.

These types describe what the router decides and what the brain returns.
Perception emits Triaged events; cognition turns them into ReasonedVerdicts.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum


class TaskType(str, Enum):
    CLASSIFY_THREAT = "classify_threat"        # bread-and-butter triage; Sonnet
    DEEP_INCIDENT = "deep_incident"            # post-mortem reasoning; Opus
    REALTIME_INTEL = "realtime_intel"          # X/Twitter signals; Grok
    MALWARE_ANALYZE = "malware_analyze"        # raw exploit code; Venice (uncensored)
    SENSITIVE_ANALYZE = "sensitive_analyze"    # never logged by provider; Venice (TEE)
    FORMAT_POST = "format_post"                # render to voice; Haiku
    SUMMARIZE = "summarize"                    # nightly batch; Sonnet


class Sensitivity(str, Enum):
    PUBLIC = "public"
    SENSITIVE = "sensitive"
    CONFIDENTIAL = "confidential"


class Urgency(str, Enum):
    REALTIME = "realtime"
    BATCH = "batch"


class Complexity(str, Enum):
    SIMPLE = "simple"
    MODERATE = "moderate"
    DEEP = "deep"


class ThreatClass(str, Enum):
    HONEYPOT = "honeypot"
    PHISHING_APPROVAL = "phishing_approval"
    RUGPULL = "rugpull"
    EXPLOIT_CONTRACT = "exploit_contract"
    GOVERNANCE_ATTACK = "governance_attack"
    PROMPT_INJECTION = "prompt_injection"
    UNKNOWN = "unknown"
    BENIGN = "benign"


@dataclass(frozen=True)
class Task:
    type: TaskType
    sensitivity: Sensitivity
    urgency: Urgency
    complexity: Complexity
    subject: str
    instruction: str
    context: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class BrainResponse:
    brain: str           # "claude:opus", "grok:4", "venice:uncensored"
    text: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cost_usd: float = 0.0
    latency_ms: int = 0


@dataclass(frozen=True)
class Threat:
    threat_class: ThreatClass
    target: str          # contract address, tx hash, CVE id, etc.
    severity: int        # 0-100
    confidence: float    # 0.0-1.0
    summary: str
    evidence: tuple[str, ...] = field(default_factory=tuple)
    chain_refs: tuple[str, ...] = field(default_factory=tuple)
    classified_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True)
class ReasonedVerdict:
    threat: Threat
    brain: str
    reasoning: str
    raw_response: str | None = None
