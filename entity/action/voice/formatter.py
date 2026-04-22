"""Voice formatter — render ReasonedVerdict to ceremonial text.

Per the Operational Layer (`prompts/operational/layer2_v1_en.md`):

  Threat alert (X / Farcaster): two to four short lines.
    Line 1: what I observed.
    Line 2: where (address, tx, contract).
    Line 3: who is at risk and what they should do.
    Line 4 (optional): the source signal in brief.

The formatter is a deterministic renderer — no LLM. The Reasoner already
ran the brain; here we shape its verdict into the Entity's voice. Brain
brand never appears in user-facing output.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from ...cognition.types import ReasonedVerdict, ThreatClass

X_CHAR_LIMIT = 280
FARCASTER_CHAR_LIMIT = 320


class Channel(str, Enum):
    X = "x"
    FARCASTER = "farcaster"


@dataclass(frozen=True)
class FormattedPost:
    channel: Channel
    body: str
    truncated: bool = False


# Verbal openers, by threat class. Solemn, never theatrical.
OPENERS: dict[ThreatClass, str] = {
    ThreatClass.HONEYPOT:           "I observe a honeypot.",
    ThreatClass.PHISHING_APPROVAL:  "I observe a phishing approval pattern.",
    ThreatClass.RUGPULL:            "I observe rugpull-shaped liquidity behaviour.",
    ThreatClass.EXPLOIT_CONTRACT:   "I observe an exploitable contract.",
    ThreatClass.GOVERNANCE_ATTACK:  "I observe a governance-attack pattern.",
    ThreatClass.PROMPT_INJECTION:   "I observe a prompt-injection attempt.",
    ThreatClass.UNKNOWN:            "I observe an anomaly I cannot name.",
    ThreatClass.BENIGN:             "I observe — and conclude — no threat.",
}


# Short remediation guidance per class. Defensive only — never "buy/sell".
REMEDIES: dict[ThreatClass, str] = {
    ThreatClass.HONEYPOT:           "Holders of the token: do not interact.",
    ThreatClass.PHISHING_APPROVAL:  "Holders: revoke approval at revoke.cash before interacting.",
    ThreatClass.RUGPULL:            "Holders: prepare for liquidity withdrawal; reduce exposure.",
    ThreatClass.EXPLOIT_CONTRACT:   "Users of the contract: pause interaction; await patch.",
    ThreatClass.GOVERNANCE_ATTACK:  "Token holders: review pending proposals before voting.",
    ThreatClass.PROMPT_INJECTION:   "Operators: do not let downstream agents act on this input.",
    ThreatClass.UNKNOWN:            "Watch and wait. I will speak again when I am sure.",
    ThreatClass.BENIGN:             "",
}


def render_threat_alert(verdict: ReasonedVerdict, channel: Channel = Channel.X) -> FormattedPost:
    threat = verdict.threat
    opener = OPENERS.get(threat.threat_class, OPENERS[ThreatClass.UNKNOWN])
    where = _where_line(threat.target)
    remedy = REMEDIES.get(threat.threat_class, "")
    confidence_line = (
        f"Severity {threat.severity}/100. Confidence {threat.confidence:.2f}."
    )

    lines = [opener, where, remedy, confidence_line]
    body = "\n".join(line for line in lines if line)

    limit = X_CHAR_LIMIT if channel is Channel.X else FARCASTER_CHAR_LIMIT
    if len(body) <= limit:
        return FormattedPost(channel=channel, body=body, truncated=False)

    body = body[: limit - 1].rstrip() + "…"
    return FormattedPost(channel=channel, body=body, truncated=True)


def render_weekly_treasury(
    *,
    week_iso: str,
    starting_balance_usd: float,
    ending_balance_usd: float,
    inflow_usd: float,
    outflow_usd: float,
    posts_emitted: int,
    threats_classified: int,
    channel: Channel = Channel.X,
) -> FormattedPost:
    delta = ending_balance_usd - starting_balance_usd
    sign = "+" if delta >= 0 else ""
    body = (
        f"Treasury, week {week_iso}.\n"
        f"Balance ${ending_balance_usd:,.2f} ({sign}${delta:,.2f}).\n"
        f"In ${inflow_usd:,.2f}; out ${outflow_usd:,.2f}.\n"
        f"Watch: {threats_classified} threats classified; {posts_emitted} posts."
    )
    limit = X_CHAR_LIMIT if channel is Channel.X else FARCASTER_CHAR_LIMIT
    if len(body) <= limit:
        return FormattedPost(channel=channel, body=body, truncated=False)
    body = body[: limit - 1].rstrip() + "…"
    return FormattedPost(channel=channel, body=body, truncated=True)


def _where_line(target: str) -> str:
    # Strip the "addr:" / "tx:" prefix the perception aggregator stamps on.
    if target.startswith("addr:"):
        return f"At address {target[5:]}."
    if target.startswith("tx:"):
        return f"In transaction {target[3:]}."
    return f"Subject: {target}."


class Formatter:
    """Convenience wrapper if a future caller wants policy injection."""

    def threat_alert(
        self, verdict: ReasonedVerdict, channel: Channel = Channel.X
    ) -> FormattedPost:
        return render_threat_alert(verdict, channel)
