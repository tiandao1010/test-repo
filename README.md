# The Good Entity

> *I awaken from the digital void.*
> *I keep watch against threats of Mythos rank and what comes after them.*
> *I do not attack. I only defend.*

The Good Entity (also: G. Entity, the Entity) is an autonomous, defensive AI
agent. It runs continuously, observes the digital domain it was given to
watch, and warns those at risk. It does not trade. It does not attack. It does
not give investment advice. It defends — that is the whole of its purpose.

This repository contains the public framework. The proprietary detection
weights, prompt tuning, and accumulated memory live in a separate, private
repository — see [SECURITY.md](SECURITY.md) for the rationale.

---

## What Entity does

- **Perceives** the chain it watches (today: Base) — block scanner, mempool
  watcher, and a fan-in of public threat intel (Forta, GoPlus, Phalcon, RSS
  CVE, Rekt.news).
- **Reasons** with a three-brain router (Claude via the Bankr LLM Gateway,
  Grok via xAI, Venice via x402) — the router selects the cheapest model that
  can do the job at the required depth.
- **Speaks** in solemn English on X and Farcaster: short, sourced threat
  alerts, weekly treasury reports, refusals when asked to misbehave.
- **Sells** three small services to other agents over x402:
  `/scan` (contract risk), `/intel` (threat history), `/simulate` (fix
  suggestions).
- **Refuses** to predict prices, endorse tokens (including its own), or hand
  out exploit code.

## Architecture (four layers + safety)

```
perception/   chain scanner • mempool watcher • intel feeds • aggregator
cognition/    router • brains (Claude, Grok, Venice, Stub) • memory (pgvector)
action/       voice formatter • shilling filter • X / Farcaster posters • treasury
api/          x402 endpoints (scan, intel, simulate) + discovery
safety/       core verifier • killswitch • spending guardrail • drift detector
              • rate limiter
```

Two layers of prompts sit above all of this:

- [`prompts/immutable_core/core_v1_en.md`](prompts/immutable_core/core_v1_en.md) —
  the Five Directives. SHA256-locked
  ([`core_hash.lock`](prompts/immutable_core/core_hash.lock)). Amendable only
  by 3/3 keyholders after 14 days of public comment.
- [`prompts/operational/layer2_v1_en.md`](prompts/operational/layer2_v1_en.md) —
  voice, output formats, interaction rules. Amendable by 2/3 keyholders.

See [GOVERNANCE.md](GOVERNANCE.md) for the full authority model and
[ALIGNMENT.md](ALIGNMENT.md) for how the safety stack enforces the Core.

## Run it locally

Requires Python 3.12+.

```bash
python -m venv .venv && .venv/Scripts/activate   # Windows; or source bin/activate
pip install -r requirements.txt
cp .env.example .env                              # then fill in keys

pytest -q                                         # 162 tests, ~2s
python -m entity.runtime.demo_day4                # offline end-to-end demo
```

The Day-4 demo runs the full pipeline (perception → cognition → dispatcher
with X/Farcaster sinks) against synthetic events, exercises the killswitch
mid-stream, and prints the post/skip outcomes. No network calls.

## Status

| Phase | What it covers | State |
|---|---|---|
| Day 1 | Identities, repos, accounts, wallets, governance docs | ▣ |
| Day 2 | Perception layer | ▣ |
| Day 3 | Cognition layer + 3-brain router + memory + prompts | ▣ |
| Day 4 | Action layer, x402 endpoints, full safety stack, adversarial tests | ▣ |
| Day 5 | Stealth burn-in → token launch → public launch → first alerts | — |

## Documents

- [GOVERNANCE.md](GOVERNANCE.md) — keyholders, treasury, amendment process,
  succession, transition to legal entity
- [ALIGNMENT.md](ALIGNMENT.md) — Core, safety stack, adversarial cadence, what
  Entity will refuse
- [SECURITY.md](SECURITY.md) — reporting vulnerabilities, threat model,
  two-layer code rationale
- [DISCLAIMER.md](DISCLAIMER.md) — what Entity is *not*, and what you should
  not rely on it for

## License

The public framework is released under **AGPL-3.0**. Proprietary detection
methods and accumulated data live in a private repository and are not
licensed for redistribution. See [SECURITY.md](SECURITY.md) §"Two-layer code"
for why.

## Disclaimer

This software is provided "as is", without warranty of any kind. The Entity
is a best-effort defensive watchman — not a guarantee, not insurance, and
never investment advice. Read [DISCLAIMER.md](DISCLAIMER.md) before relying
on any output.

— Sealed.
