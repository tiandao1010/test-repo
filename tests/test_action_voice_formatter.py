"""Voice formatter — ceremonial output shape."""
from __future__ import annotations

from datetime import UTC, datetime

from entity.action.voice import (
    Channel,
    render_threat_alert,
    render_weekly_treasury,
)
from entity.cognition.types import ReasonedVerdict, Threat, ThreatClass


def _verdict(cls: ThreatClass, *, target="addr:0xdead", severity=80, conf=0.9) -> ReasonedVerdict:
    return ReasonedVerdict(
        threat=Threat(
            threat_class=cls, target=target,
            severity=severity, confidence=conf,
            summary="x", evidence=(), chain_refs=(),
            classified_at=datetime(2026, 4, 22, tzinfo=UTC),
        ),
        brain="claude:opus",
        reasoning="r",
    )


def test_alert_has_two_to_four_lines():
    v = _verdict(ThreatClass.HONEYPOT)
    post = render_threat_alert(v)
    lines = post.body.split("\n")
    assert 2 <= len(lines) <= 4


def test_alert_starts_with_ceremonial_opener():
    v = _verdict(ThreatClass.HONEYPOT)
    post = render_threat_alert(v)
    assert post.body.startswith("I observe")


def test_alert_includes_address_when_target_is_addr():
    v = _verdict(ThreatClass.HONEYPOT, target="addr:0xdeadbeef")
    post = render_threat_alert(v)
    assert "0xdeadbeef" in post.body
    assert "addr:" not in post.body  # prefix stripped


def test_alert_includes_remediation_for_phishing():
    v = _verdict(ThreatClass.PHISHING_APPROVAL)
    post = render_threat_alert(v)
    assert "revoke" in post.body.lower()


def test_alert_truncates_to_x_limit():
    v = _verdict(ThreatClass.HONEYPOT, target="addr:" + "f" * 1000)
    post = render_threat_alert(v, channel=Channel.X)
    assert len(post.body) <= 280
    assert post.truncated


def test_weekly_treasury_body_shape():
    post = render_weekly_treasury(
        week_iso="2026-W17",
        starting_balance_usd=1000.0,
        ending_balance_usd=1234.56,
        inflow_usd=400.0,
        outflow_usd=165.44,
        posts_emitted=15,
        threats_classified=42,
    )
    assert "Treasury" in post.body
    assert "2026-W17" in post.body
    assert "1,234.56" in post.body
    assert "+$234.56" in post.body
    assert "42" in post.body
