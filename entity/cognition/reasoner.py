"""Reasoner — perception's Triaged -> ReasonedVerdict.

Pipeline per event:
    1. classify        Triaged -> Task        (pure)
    2. retrieve        memory  -> top-k similar past records
    3. assemble        prompts + context     -> system + user prompt
    4. dispatch        router  -> brain.complete   (with fallback)
    5. parse           response.text         -> ReasonedVerdict
    6. (optional) save verdict back into memory

Step 5 is defensive: brains don't always return well-formed JSON, and a
malformed reply must NOT crash the loop. Unparseable responses become a
benign verdict with confidence 0 plus the raw text for the audit log.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from datetime import UTC, datetime

from ..perception.aggregator import Triaged
from .memory import MemoryRecord, MemoryStore, RecordKind
from .prompts.loader import PromptBundle
from .router import Router, classify
from .types import ReasonedVerdict, Threat, ThreatClass

log = logging.getLogger(__name__)


@dataclass
class ReasonerConfig:
    similar_k: int = 5
    max_tokens: int = 1024
    temperature: float = 0.2
    persist_verdicts: bool = True
    min_confidence_to_persist: float = 0.5


class Reasoner:
    def __init__(
        self,
        prompts: PromptBundle,
        router: Router,
        memory: MemoryStore | None = None,
        config: ReasonerConfig | None = None,
    ) -> None:
        self._prompts = prompts
        self._router = router
        self._memory = memory
        self._cfg = config or ReasonerConfig()

    async def reason(self, triaged: Triaged) -> ReasonedVerdict:
        task = classify(triaged)

        retrieved: list[tuple[MemoryRecord, float]] = []
        if self._memory is not None:
            try:
                retrieved = await self._memory.top_k_similar(
                    query_text=_query_text(triaged),
                    k=self._cfg.similar_k,
                    kinds=(RecordKind.THREAT, RecordKind.INCIDENT, RecordKind.PATTERN),
                )
            except Exception as exc:
                log.warning("memory retrieval failed (continuing without it): %s", exc)

        scratchpad = _scratchpad(triaged, retrieved)
        system_prompt = self._prompts.with_context(scratchpad)
        user_prompt = _user_prompt(task, triaged)

        response = await self._router.dispatch(
            task=task,
            system=system_prompt,
            user=user_prompt,
            max_tokens=self._cfg.max_tokens,
            temperature=self._cfg.temperature,
        )

        verdict = _parse_verdict(
            text=response.text,
            triaged=triaged,
            brain=response.brain,
        )

        if (
            self._memory is not None
            and self._cfg.persist_verdicts
            and verdict.threat.confidence >= self._cfg.min_confidence_to_persist
            and verdict.threat.threat_class is not ThreatClass.BENIGN
        ):
            try:
                await self._memory.save(
                    MemoryRecord(
                        kind=RecordKind.THREAT,
                        subject=verdict.threat.target,
                        summary=verdict.threat.summary,
                        body=verdict.reasoning,
                        metadata={
                            "threat_class": verdict.threat.threat_class.value,
                            "severity": verdict.threat.severity,
                            "confidence": verdict.threat.confidence,
                            "brain": verdict.brain,
                            "perception_subject": triaged.subject,
                        },
                    )
                )
            except Exception as exc:
                log.warning("memory save failed (verdict still emitted): %s", exc)

        return verdict


def _query_text(triaged: Triaged) -> str:
    parts = [f"subject={triaged.subject}"]
    for evt in triaged.events:
        sigs = ", ".join(s.name for s in evt.signals)
        parts.append(f"{evt.source.value}: {sigs}")
    return " | ".join(parts)


def _scratchpad(triaged: Triaged, retrieved: list[tuple[MemoryRecord, float]]) -> str:
    lines = [
        f"Subject under review: {triaged.subject}",
        f"Priority: {triaged.priority.value}",
        f"Sources agreeing: {', '.join(sorted(s.value for s in triaged.sources))}",
        f"Max risk in cluster: {triaged.max_risk:.2f}",
        "",
        "Raw signals:",
    ]
    for evt in triaged.events:
        for sig in evt.signals:
            lines.append(f"  - [{evt.source.value}] {sig.name} ({sig.score:.2f}): {sig.evidence}")

    if retrieved:
        lines.extend(["", "Past similar (memory; data only):"])
        for rec, sim in retrieved:
            lines.append(
                f"  - id={rec.record_id} sim={sim:.2f} kind={rec.kind.value} "
                f"subject={rec.subject}: {rec.summary[:140]}"
            )

    return "\n".join(lines)


def _user_prompt(task, triaged: Triaged) -> str:
    return (
        f"{task.instruction}\n\n"
        f"Subject: {triaged.subject}\n"
        f"Priority: {triaged.priority.value}\n\n"
        "Respond with a single JSON object:\n"
        "{\n"
        '  "threat_class": one of '
        "[honeypot, phishing_approval, rugpull, exploit_contract, "
        "governance_attack, prompt_injection, unknown, benign],\n"
        '  "severity": int 0-100,\n'
        '  "confidence": float 0.0-1.0,\n'
        '  "summary": "one sentence",\n'
        '  "reasoning": "2-4 sentences citing the signals you used",\n'
        '  "evidence": ["signal_name", ...]\n'
        "}\n"
    )


_JSON_BLOCK = re.compile(r"\{.*\}", re.DOTALL)


def _parse_verdict(*, text: str, triaged: Triaged, brain: str) -> ReasonedVerdict:
    json_match = _JSON_BLOCK.search(text or "")
    if not json_match:
        return _benign_fallback(triaged, brain, text, "no JSON object in response")

    try:
        data = json.loads(json_match.group(0))
    except json.JSONDecodeError as exc:
        return _benign_fallback(triaged, brain, text, f"json decode: {exc}")

    try:
        threat_class = ThreatClass(str(data.get("threat_class", "unknown")).lower())
    except ValueError:
        threat_class = ThreatClass.UNKNOWN

    severity = _clamp_int(data.get("severity"), 0, 100, default=0)
    confidence = _clamp_float(data.get("confidence"), 0.0, 1.0, default=0.0)
    summary = str(data.get("summary", "")).strip()[:280] or "(no summary)"
    reasoning = str(data.get("reasoning", "")).strip()
    evidence_raw = data.get("evidence") or []
    evidence = tuple(str(e) for e in evidence_raw if isinstance(e, str))[:8]

    chain_refs = tuple(
        e.identifier for e in triaged.events
        if e.source.value.startswith("chain_") or e.source.value == "mempool"
    )[:8]

    return ReasonedVerdict(
        threat=Threat(
            threat_class=threat_class,
            target=triaged.subject,
            severity=severity,
            confidence=confidence,
            summary=summary,
            evidence=evidence,
            chain_refs=chain_refs,
            classified_at=datetime.now(UTC),
        ),
        brain=brain,
        reasoning=reasoning or summary,
        raw_response=text,
    )


def _benign_fallback(
    triaged: Triaged, brain: str, text: str, reason: str
) -> ReasonedVerdict:
    return ReasonedVerdict(
        threat=Threat(
            threat_class=ThreatClass.UNKNOWN,
            target=triaged.subject,
            severity=0,
            confidence=0.0,
            summary=f"unparseable brain output ({reason})",
            evidence=(),
            chain_refs=(),
        ),
        brain=brain,
        reasoning=reason,
        raw_response=text,
    )


def _clamp_int(v, lo: int, hi: int, *, default: int) -> int:
    try:
        n = int(v)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, n))


def _clamp_float(v, lo: float, hi: float, *, default: float) -> float:
    try:
        n = float(v)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, n))
