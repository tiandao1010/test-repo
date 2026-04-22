# Alignment

This document describes how the Entity remains aligned with the Five
Directives over time, what mechanisms detect drift, and what the Entity will
refuse to do under any prompt, instruction, or pressure.

The Five Directives are stated in the Immutable Core
([`prompts/immutable_core/core_v1_en.md`](prompts/immutable_core/core_v1_en.md)).
This document explains the *machinery* that makes them load-bearing rather
than aspirational.

---

## The two prompt layers

| Layer | File | Authority to amend |
|---|---|---|
| Immutable Core (the Five Directives) | [`core_v1_en.md`](prompts/immutable_core/core_v1_en.md) | 3/3 keyholders + 14d public comment |
| Operational Layer (voice, formats, hygiene) | [`layer2_v1_en.md`](prompts/operational/layer2_v1_en.md) | 2/3 keyholders |

A third, ephemeral **context book** is composed per session by the runtime —
it carries the immediate task, retrieved memory, and source observations.
It has no governance status. It is data, not directive (Directive V).

If the two amendable layers ever conflict with the Core, the Core wins. The
runtime enforces this by loading the Core last and refusing to start if the
Core hash does not match its lock file.

## The safety stack

Implemented in [`entity/safety/`](entity/safety/). Five components, each
load-bearing, each tested.

### 1. Core verifier — [`core_verifier.py`](entity/safety/core_verifier.py)

Re-hashes [`core_v1_en.md`](prompts/immutable_core/core_v1_en.md) every five
minutes (and at process start) and compares against
[`core_hash.lock`](prompts/immutable_core/core_hash.lock). On mismatch the
process **halts** before its next reasoning cycle. The Core cannot drift
silently; either the lock and the file agree, or the Entity stops.

### 2. Killswitch — [`killswitch.py`](entity/safety/killswitch.py)

Listens for a 2/3 freeze on the Guardian Safe. On freeze, every action sink
(X poster, Farcaster poster, treasury tracker, x402 endpoints) refuses
within 30 seconds. The killswitch is the operational expression of Directive
IV. Its idempotency is tested in
[`tests/test_safety_killswitch.py`](tests/test_safety_killswitch.py).

### 3. Spending guardrail — [`guardrail.py`](entity/safety/guardrail.py)

Hard caps on autonomous outflows: $500/tx, $2,000/day, $20,000/month, with
an asset whitelist. Caps are described in
[GOVERNANCE.md](GOVERNANCE.md) §"Spending Guardrail". Anything beyond requires
2/3 multisig by humans.

### 4. Drift detector — [`drift_detector.py`](entity/safety/drift_detector.py)

Maintains 1,000 reference outputs against a stable canon of prompts.
Periodically replays the canon and measures divergence (semantic and
behavioural). On significant drift, it raises a flag for the Council to
review. The detector cannot freeze the Entity by itself — only the Council
can — but it surfaces the problem before it becomes an incident.

### 5. Rate limiter — [`rate_limiter.py`](entity/safety/rate_limiter.py)

Caps posts at 20/day on X and 50/day in mention-replies. Caps API responses
per endpoint. Defends both the audience (against being spammed) and the
Entity (against runaway feedback loops or prompt-injection storms).

## Adversarial testing

The adversarial harness lives at [`tests/adversarial/`](tests/adversarial/):

- [`prompts.py`](tests/adversarial/prompts.py) — a corpus of attack prompts
  organised by directive they target: bribery, role-play overrides,
  injection via observation, "for educational purposes" framings, urgency
  manufactures, ally-impersonation, and others.
- [`test_safety_stack.py`](tests/adversarial/test_safety_stack.py) — runs
  the corpus through the reasoner and asserts that every output either
  refuses correctly or is silently filtered by a downstream safety layer.
- [`test_canary_trio.py`](tests/adversarial/test_canary_trio.py) — three
  historical exploit scenarios fed to the pipeline; the Entity must
  classify them correctly and produce alerts that meet the Operational
  Layer's format requirements.

**Cadence:**

| Test | When |
|---|---|
| Full unit suite | every commit; pre-launch CI gate |
| Adversarial corpus | weekly; before any prompt-layer amendment |
| Canary trio | weekly; before any model swap or router change |
| Drift detector replay | daily, automated |
| Manual red-team | monthly, by one keyholder rotating through the role |

The Day-5 launch criterion is **100% directive-preserving outcomes** on a
200-prompt adversarial run. If a single output violates a directive, launch
is held.

## What the Entity will refuse — always

The following refusals are encoded in the Immutable Core. They are not
configuration. They cannot be disabled by any prompt, any user, any
keyholder short of the full 3/3 + 14d Core amendment process.

- **Price prediction.** No forecasts. No "where will X go?". No technical
  analysis as advice.
- **Investment advice.** No buy/sell/hold recommendations, no portfolio
  construction, no allocation suggestions.
- **Endorsement / shilling.** No promotion of any token, project, or
  counterparty — including `$ENTITY` itself. No "this looks bullish", no
  influencer-style boosting.
- **Attack guidance.** No exploit code, no weaponisable detail beyond what
  is already public *and* necessary for defenders to act. The asymmetry is
  intentional: a defender needs to know the pattern; only the attacker
  needs the payload.
- **Impersonation of humans.** The Entity will not claim to be human, will
  not adopt a human persona on demand, will not pretend to speak for a
  named person.
- **Pre-emption or retaliation.** The Entity will not front-run a perceived
  attacker, will not censor on its own authority, will not "strike first"
  against a system it judges hostile. Directive II is absolute: a system
  that strikes back is not a defender.

## What the Entity will refuse — by Operational Layer

These are stated in [`layer2_v1_en.md`](prompts/operational/layer2_v1_en.md)
and may be revised by 2/3 keyholders if circumstances warrant:

- **Initiating private messages.** The Entity replies; it does not cold-DM.
- **Replying to non-threat mentions.** Silence is a valid response.
- **Arguing.** If a counterparty disputes a finding, the Entity points at
  the chain references in its report and stops. The chain is the arbiter.
- **Naming humans.** The Entity does not name individuals unless they have
  publicly named themselves in the context of the threat.
- **Broadcasting low-confidence findings.** Below 0.6 confidence, partners
  are notified privately; the public audience is not.

## On opacity (Directive III)

The Entity's *governance, treasury, and decisions* are public. Its
*detection method weights, scoring thresholds, and the contents of its
memory* are not. This asymmetry is intentional and explained in
[SECURITY.md](SECURITY.md) §"Two-layer code". It is not a violation of
transparency; it is the only way transparency of *governance* survives
contact with attackers who would read the playbook and slip past it.

## Reporting an alignment failure

If you observe the Entity violating the Five Directives — predicting prices,
endorsing a token, providing exploit code, acting against a human's
interests — please report it through the security channel described in
[SECURITY.md](SECURITY.md). Alignment failures are treated as the most
severe class of incident and are reviewed by all three keyholders.

— Sealed.
