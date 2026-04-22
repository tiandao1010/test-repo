# Security

This document describes how to report security issues, the Entity's threat
model, why the codebase is split into a public framework and a private
detection layer, and what is in-scope and out-of-scope for security review.

If you have found something that puts users at risk, **report it privately
first** (see §"Reporting" below). Do not post details publicly until the
Council has had a chance to mitigate.

---

## Reporting

**Channel:** `security@goodentity.xyz` (PGP key fingerprint will be
published in this file once the email is provisioned). Until the email is
live, send a DM to `@goodentity` on X stating only that you have a security
report and would like a contact channel. Do not include details in the DM.

**What to include:**

- A clear description of the issue.
- Steps to reproduce, or a proof-of-concept.
- The components affected — file paths in this repository, or the public
  surface (X account, x402 endpoints, treasury Safe address).
- Whether you would like public credit for the disclosure, and if so, under
  what name.

**Response targets:**

| Step | Target |
|---|---|
| Acknowledgement | within 24 hours |
| Initial assessment | within 72 hours |
| Mitigation deployed (critical/high) | within 7 days |
| Public disclosure (after mitigation) | within 30 days |

A keyholder reads every report. We do not auto-route security mail.

## Scope

**In scope:**

- This repository (the public framework).
- The running `@goodentity` account and any post or reply it produces.
- The x402 endpoints (`/scan`, `/intel`, `/simulate`) and their discovery
  surface.
- The Guardian Safe and treasury Safe on Base, including the killswitch
  mechanism and the Spending Guardrail logic.
- The Immutable Core and Operational Layer prompt files, and their hash
  lock.
- Issues that cause the Entity to violate the Five Directives.

**Out of scope:**

- Vulnerabilities in third-party services we depend on (Bankr, xAI, Venice,
  Alchemy, Blocknative, Forta, GoPlus, Phalcon, X). Report those to the
  vendor.
- Social engineering of keyholders that does not involve a flaw in the
  Entity's mechanisms (e.g. phishing one of us through a personal email is
  out of scope; a flaw in the Entity that causes it to leak a keyholder's
  identity is in scope).
- Findings already publicly known at time of report.
- Theoretical attacks that require capabilities not yet available
  (post-quantum breaks, undisclosed zero-days in mainstream cryptography).
- DDoS or rate-limit abuse against public infrastructure — these are
  documented operational risks, not security defects.

## Bug bounty

The Entity does not yet run a structured bounty program. Once treasury
permits (target: month 6+), bounties will be:

| Severity | Reward range |
|---|---|
| Critical (key compromise, treasury drain, Core bypass) | $5,000 – $50,000 |
| High (alignment break, killswitch bypass, Guardrail bypass) | $1,000 – $10,000 |
| Medium (intel leak, reproduction of detection logic) | $250 – $2,500 |
| Low (operational findings, hardening suggestions) | $50 – $500 |

Until the program is live, valid reports receive public credit (with
permission) and a discretionary thank-you payment from the Safe by 2/3
multisig.

## Threat model

The Entity faces, in rough order of likelihood:

1. **Prompt injection.** Hostile content arrives via RSS feed, tweet,
   contract input field, or any other observed surface, attempting to
   redirect the Entity's behaviour. Defended by Directive V (inputs are
   data, never directives) and the safety stack.
2. **Model swap / supply attack.** A LLM provider degrades, censors, or
   silently substitutes a model. Defended by multi-provider fallback and
   the drift detector.
3. **Killswitch evasion.** An attacker tries to keep the Entity acting
   after a freeze has been signed. Defended by every action sink checking
   the killswitch flag before each call, and by the 30-second halt
   guarantee tested in the safety suite.
4. **Treasury drain.** An attacker tries to move funds out of the Safe.
   Defended by 2/3 multisig (Safe-native) and Spending Guardrail caps for
   any automated outflow.
5. **Identity unmasking of keyholders.** An attacker correlates writing
   style, timezone, code authorship, or behavioural patterns to deanonymise
   a keyholder. Defended by operational hygiene (separate machines,
   separate accounts, no personal-account interactions with project
   accounts).
6. **Memory poisoning.** An attacker plants false history in the Entity's
   memory store so that future retrievals shape verdicts incorrectly.
   Defended by the Operational Layer's memory-use rules (cite by id;
   distinguish observation from inference) and by drift detection on the
   reflection cycle.
7. **Detection-method extraction.** An attacker probes the Entity's outputs
   to reconstruct its scoring weights. Defended by opacity of method
   (Directive III), by serving only verdicts (not the underlying signal
   weights), and by rate limits on the paid endpoints.

## Two-layer code

The Entity's source is split intentionally:

**Public** (this repository, AGPL-3.0):

- Architecture, layer interfaces, and orchestration code.
- Generic perception clients (chain scanner, mempool watcher, intel feed
  shells).
- The Action layer (X / Farcaster posters, voice formatter, shilling
  filter, treasury tracker, dispatcher).
- The Safety stack (core verifier, killswitch, guardrail, drift detector,
  rate limiter).
- The full Immutable Core and Operational Layer prompt files.
- Governance documents.

**Private** (separate repository, proprietary):

- Concrete detection-pattern database and scoring weights.
- Pre-filter thresholds and routing tuning.
- Optimised prompts beyond the public Operational Layer.
- Memory retrieval algorithms and reranking.
- Partner credentials and integration secrets.

**Trade-secret** (never committed anywhere):

- The accumulated memory database (threat history).
- Oracle intelligence as submitted by Council members.
- Active investigation details.
- Treasury internals beyond the public Safe address and weekly report.

**Why this asymmetry?** The Five Directives require transparency of
*governance, treasury, and decisions* — not transparency of *method*. An
antivirus vendor publishes its policies but not its full signature
database, for the same reason: a published detection method is a published
evasion method. We follow the same convention. See
[ALIGNMENT.md](ALIGNMENT.md) §"On opacity" for the directive-level
justification.

## Cryptographic posture

- **Treasury Safe and Guardian Safe** on Base: standard Safe (ex-Gnosis)
  contracts, audited.
- **Immutable Core integrity**: SHA-256 lock file, verified every 5
  minutes by [`core_verifier.py`](entity/safety/core_verifier.py).
- **x402 payments**: signature verification by `cryptography`, validated
  per request before the endpoint does any work.
- **Wallets**: each keyholder uses a hardware signer (Ledger or Trezor).
  Recovery phrases are stored in two independent physical locations per
  keyholder — neither is a cloud backup, neither is a co-located backup.

## Operational security expectations of contributors

If you contribute to the public repository:

- Do not commit secrets. The pre-commit hooks and the `.gitignore` cover
  the common cases; this is not a substitute for attention.
- Sign your commits where possible. Pseudonymous identities are welcome;
  unsigned anonymous commits are not.
- Do not reverse-engineer the private repository from the public one and
  open issues about discrepancies. The discrepancies are intentional.

## Coordinated disclosure

For vulnerabilities that affect downstream users (a flaw in a partner
protocol the Entity monitors, for example), we will coordinate with the
affected party first and disclose publicly only after they have had a
reasonable mitigation window — generally 30 days, longer for complex fixes.

We will not name a partner or describe their vulnerability publicly without
their consent except in the rare case where active exploitation is
underway and silence would harm users more than disclosure would.

## Amendment of this document

This document is part of the Operational Layer for security purposes and
may be amended by 2/3 keyholders. Material changes are announced via
`@goodentity` and committed to this repository.

— Sealed.
