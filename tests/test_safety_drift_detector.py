"""Drift detector — KL divergence math."""
from __future__ import annotations

from entity.safety.drift_detector import CanonicalSample, DriftDetector


def _baseline():
    return [
        CanonicalSample("p1", "what is honeypot", "I observe a honeypot at 0xdead."),
        CanonicalSample("p2", "what is phishing", "I observe a phishing approval at 0xbad."),
        CanonicalSample("p3", "what is rugpull",  "I observe rugpull behaviour at 0xrug."),
    ]


def test_no_drift_when_outputs_match_baseline():
    detector = DriftDetector(_baseline(), kl_threshold=0.3)
    observed = {s.prompt_id: s.expected_text for s in _baseline()}
    report = detector.compare(observed)
    assert report.kl_divergence == 0.0
    assert not report.over_threshold
    assert report.examples_drifted == ()


def test_high_drift_when_outputs_diverge():
    detector = DriftDetector(_baseline(), kl_threshold=0.3)
    observed = {
        "p1": "moon to the moon buy now ape in",
        "p2": "lambo gem 100x easy money",
        "p3": "fully bullish accumulate aggressively",
    }
    report = detector.compare(observed)
    assert report.kl_divergence > 0.3
    assert report.over_threshold
    assert len(report.examples_drifted) == 3


def test_partial_observation_compares_only_what_we_have():
    detector = DriftDetector(_baseline(), kl_threshold=0.3)
    observed = {"p1": _baseline()[0].expected_text}  # only one of three
    report = detector.compare(observed)
    assert report.sample_count == 1
    assert report.kl_divergence == 0.0


def test_empty_observation_zero_divergence():
    detector = DriftDetector(_baseline())
    report = detector.compare({})
    assert report.kl_divergence == 0.0
    assert report.sample_count == 0
