# Disclaimer

This document governs your use of The Good Entity ("Entity"), the public
software in this repository, the running agent on social platforms (currently
X as `@goodentity`), the x402 service endpoints (`/scan`, `/intel`,
`/simulate`), and the `$ENTITY` token. By interacting with any of these, you
agree to the terms below.

---

## 1. Not financial advice

Nothing the Entity says, posts, returns through an API, or signs is financial
advice, investment advice, tax advice, legal advice, or a recommendation to
buy, sell, hold, stake, mint, swap, bridge, lend, or otherwise transact in
any asset.

The Entity will refuse to predict prices and will refuse to endorse, promote,
or "shill" any token, project, or counterparty — **including its own token
`$ENTITY`**. If anything in its output is read as an endorsement, that
reading is wrong.

## 2. The `$ENTITY` token

`$ENTITY` is a community/governance token launched as a fair launch through
the Bankr agent platform on Base. There is no team allocation, no presale,
and no roadmap of price-supporting actions. The token has no claim on the
treasury, no profit share, no dividend, no buy-back commitment, and no
guarantee of liquidity.

`$ENTITY` is not a security in any jurisdiction it is offered in, to the
maximum extent permitted by law. If your jurisdiction would treat it as one,
do not acquire it.

Holding `$ENTITY` confers community standing only. Operational authority over
the Entity rests with the Keyholder Council (see [GOVERNANCE.md](GOVERNANCE.md)),
not with token holders.

## 3. Defensive monitoring is best-effort

The Entity watches public chain data and public threat intelligence and
broadcasts what it believes it has observed. It is wrong sometimes. It is
late sometimes. It is silent sometimes — by design (see Operational Layer
§"Reasoning hygiene": below 0.6 confidence, no public broadcast).

There is **no service-level commitment**. There is no guarantee of uptime,
coverage, completeness, or accuracy. The absence of a warning from the
Entity is not an assurance of safety.

If you act on an Entity alert, verify it against on-chain data and other
sources before doing anything irreversible.

## 4. Paid endpoints

The `/scan`, `/intel`, and `/simulate` endpoints accept x402 payments in
USDC. The fee buys a single best-effort response. It does not buy:

- a guarantee that the response is correct;
- a guarantee that the contract analysed is safe (or unsafe);
- support, escalation, or human review;
- a refund if the response disappoints you.

Use small amounts on low-stakes contracts before relying on these endpoints
in any workflow that moves real money.

## 5. No warranty, no liability

The software in this repository is provided "AS IS", without warranty of any
kind, express or implied, including but not limited to merchantability,
fitness for a particular purpose, and non-infringement.

To the maximum extent permitted by applicable law, the Entity, its
keyholders, contributors, and successors-in-interest disclaim all liability
for any direct, indirect, incidental, special, consequential, or exemplary
damages arising from use of the software, the running agent, the endpoints,
or the token — including loss of funds, loss of opportunity, regulatory
exposure, and reputational harm.

This applies whether or not the Entity warned you, failed to warn you,
warned you incorrectly, or was offline at the moment you needed it.

## 6. Pseudonymity and successor-in-interest

The current keyholders operate pseudonymously. They are an unincorporated
collective in Phase 0 (see [GOVERNANCE.md](GOVERNANCE.md) §"Phases"). When a
legal entity is established, that entity becomes the successor-in-interest
for the Entity's intellectual property, treasury, and obligations. This
disclaimer transfers with that succession.

## 7. Jurisdiction

The Entity is a global, internet-native project. It is your responsibility
to determine whether interacting with it — including holding `$ENTITY` or
calling the paid endpoints — is lawful in your jurisdiction. Do not interact
with the Entity if it is not.

## 8. Updates to this disclaimer

This disclaimer may be updated. Material changes will be announced via
`@goodentity` on X and committed to this repository. Continued use after a
material change constitutes acceptance.

— Sealed.
