# ChipIn - Recommendation Agent

**Let's find tennis balls that meet your tennis crew's demanding constraints!**

ChipIn is a recommendation agent built on **AAuth**. Tell it what tennis balls you prefer (brands, one case size, a max cost). It searches real stores, keeps only what fits, and hands you a ranked shortlist. You decide whether to buy.

It demonstrates AAuth's **federated (four-party) access** model, [draft-hardt-oauth-aauth-protocol-11](https://aauth-dev.github.io/aauth-go/releases/v0.2.0/), with [aauth-go v0.2.0](https://github.com/aauth-dev/aauth-go), working with real services:

| Party | Role | |
|---|---|---|
| 🤖 Recommendation agent | AAuth agent | `chipin agent` (`internal/agent`) |
| 🙋 Player | Person | signs in once with Hellō |
| 🛡️ [Hellō](https://person.hello.coop) | Person server | identifies the player (directed `sub`) |
| 🏪 ChipIn | Resource (MCP server), agent provider, access server, on one origin | `chipin serve` (`internal/shop`, `internal/trust`) |
| 🔐 [Keycard](https://keycard.ai) | Mission enforcement | the player's constraints as a Cedar policy (`internal/keycard`) |
| 🛒 Tennis Express, Holabird Sports | Stores, over [UCP](https://ucp.dev) | live catalog, read-only (`internal/ucp`) |
| 💳 Stripe | Payment, optional | shared payment token, sandbox (`internal/payments`) |

- **Walkthrough:** https://chipin.aauth.tech/flow/ (toggle Approved / Denied)
- **Every message:** https://chipin.aauth.tech/sequence/

## How it works

1. **Identity.** The agent holds its own key; ChipIn's agent provider issues it an agent token naming Hellō as the player's person server.
2. **Live catalog.** With only its agent token, the agent searches both stores over UCP.
3. **Sign in.** The player signs in with Hellō once. ChipIn sees a directed identifier, never the player's email.
4. **Mission.** The player's constraints (brands, a 12-, 18- or 24-can case, max cost) become a selection mission: ChipIn searches the stores and keeps only matching products.
5. **Approval, four-party.** The agent asks Hellō for an auth token; Hellō federates to ChipIn's access server, which checks it is the player's own proposal.
6. **Keycard.** ChipIn publishes the mission to Keycard as a Cedar policy. From then on Keycard decides what can be bought for the player.
7. **Shortlist.** Matching products, ranked by price per ball. The mission ends here by default.
8. **Guardrail.** An off-mission product (wrong brand, case size or over the max) is refused by Keycard. No payment credential is ever minted for it.
9. **Purchase, optional.** If the player chooses to buy, ChipIn's resource token carries the exact order's SHA-256 (the offer), the auth token comes back naming the same order (the acceptance), Keycard re-checks every line, and a Stripe shared payment token capped at the total pays once.

The Cedar policy Keycard evaluates for a mission:

```cedar
permit (principal, action, resource) when {
  context has scopes &&
  context.scopes.contains("chipin:selection:<mission>") &&
  (context.scopes.contains("brand:penn") || context.scopes.contains("brand:wilson")) &&
  context.scopes.contains("pack:24") &&
  context.scopes.contains("spend:within:usd:10000")
};
```

Each order line is sent as scopes (`brand:…`, `pack:…`, and `spend:within:usd:M` for every $5 step at or above the mission total), so "spending ≤ max cost" is a set-membership test.

**Tools ask for only the trust they need:**

| MCP tool | Token |
|---|---|
| `catalog_search` | agent token |
| `mission_propose`, `cart_*`, `checkout_quote` | person token |
| `mission_approve`, `checkout_authorize`, `checkout_pay` | auth token for exactly that mission or order |

## Supervisor mode

`/supervisor/` runs the same agent under a **Supervisor** (draft-11 §4). Hellō has no missions yet, so here the agent's token names ChipIn's own person server (`internal/supervisor`, aauth-go `personserver`, at `chipin-ps.aauth.tech`).

The Supervisor is the control plane, authorization only:

- **Inputs:** the mission, the mission log (the person server's own), the person's policy, and the resource's requirement: the scope ChipIn signs into its resource token (`amount:usd:N order:<hash> cases:N`).
- **Outputs:** **allow** (one case, within the auto-approve limit; the PS then federates to ChipIn's access server, where Keycard still applies), **deny** (the log already shows a purchase under the mission), **clarify** (more than one case: a question back to the agent, which withdraws and re-requests one case), **escalate** (over the limit: deferred, `requirement=approval`, until the person decides on the page).
- **Per-act approval goes away; the accountable person does not.** The person approves the mission and their policy once, and is reached again only on escalation.
- **Injected content cannot reach the decision.** The agent's justification is recorded and shown ("agent says, not an input"), never read by the policy. The "prompt-injected" behaviour on the page claims one pre-approved case while ordering two; the Supervisor clarifies from the signed requirement (`TestInjectionCannotReachTheDecision`).

The page shows the supervision log (hideable), with each decision's inputs. The protocol between a PS and a supervision server is not specified yet; here the Supervisor is in process.

## Run

Go 1.26+.

```sh
go test ./...                              # end to end, offline: local person server, fake stores, fake Stripe

# The live demo: prints the Hellō sign-in link the first time
go run ./cmd/chipin agent -brands Penn,Wilson -case 24 -max-cost 100            # shortlist only
go run ./cmd/chipin agent -brands Penn,Wilson -case 24 -max-cost 100 -buy 1 -authorize-only   # Keycard ALLOW, no payment
go run ./cmd/chipin agent ... -buy best    # buy the ★ pick (Stripe sandbox)
```

In a terminal the agent asks before buying; with no answer it buys nothing. `chipin demo` runs everything locally with a stand-in person server. `chipin record-catalog` saves live offers for offline rehearsal (`-catalog-fixture`).

Secrets come from the environment or `.env` (never committed): `CHIPIN_ENROLLMENT_SECRET` (agent installs), `STRIPE_SECRET_KEY` (sandbox only; live keys are refused), `KEYCARD_CLIENT_ID` / `KEYCARD_CLIENT_SECRET` / `KEYCARD_ZONE_ID` (without them the same rules run locally).

`chipin serve` hosts everything on one origin: `/mcp`, `/.well-known/aauth-resource.json`, `/jwks`, `/revoke`, `/orders/{hash}`, `/missions/{id}` (shop); `/.well-known/aauth-agent.json`, `/ap/*` (agent provider); `/.well-known/aauth-access.json`, `/as/*` (access server); `/.well-known/ucp/chip-in-agent.json` (UCP agent profile); the pages from `public/`. Signing keys persist in `data/`. Every response carries `X-Robots-Tag: noindex`. Deployment: `Dockerfile`, `deploy/docker-compose.yml`.

## Status

- **Verified live** (15 Oct 2026): Hellō sign-in, four-party federation from Hellō to ChipIn's access server, Keycard ALLOW and DENY, Stripe sandbox payment.
- **Purchases are demo-only.** Payment runs in Stripe's sandbox and no order is placed at the stores. A real purchase needs the player's own payment and shipping details, for example by handing off to the store's UCP checkout; that is the next step, together with a ChipIn tab in the BB Tennis app.
- **Interop notes** (raised with the AAuth author): aauth-go's `Transport` cannot declare capabilities (§11.7), so the agent adds `interaction` and re-signs; Hellō omits `Location` on polling `202`s (the agent keeps polling the same URL, §11.8.4); Hellō requires a single-string `aud`.
- No 3-, 4- or 8-packs or single cans: the stores sell 12-, 18- and 24-can cases.
