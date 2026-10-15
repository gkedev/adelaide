# Chip In: per-purchase agent authorization with AAuth

A shopping agent buys tennis balls for a player. **Every purchase is approved by the player at their own person server ([Hellō](https://person.hello.coop))**, the approval is bound to that exact order, and the payment is a **Stripe shared payment token** capped at the approved amount. The catalog is live from real retailers over **UCP**.

Live at **https://chipin.aauth.tech** · AAuth [draft-hardt-oauth-aauth-protocol-11](https://aauth-dev.github.io/aauth-go/releases/v0.2.0/) via [aauth-go v0.2.0](https://github.com/aauth-dev/aauth-go).

## The model

Following the AAuth author's guidance for purchases: the merchant issues a resource token carrying the purchase as a per-call authorization; the agent redeems it for an auth token; the person server has the person (or a supervisor) approve; the auth token is proof that *this* purchase was approved.

| Party | Role | Where |
|---|---|---|
| 🤖 Shopping agent | AAuth agent | `chipin agent` (`internal/agent`) |
| 🙋 Player (G, and others) | Person | signs in and approves at Hellō |
| 🛡️ Hellō | Person Server | `https://person.hello.coop` |
| 🏪 Chip In | Resource (MCP server) + Agent Provider + Access Server, one origin | `chipin serve` (`internal/shop`, `internal/trust`) |
| 🛒 Tennis Express, Holabird Sports | UCP businesses (live, read-only) | `internal/ucp` |
| 💳 Stripe sandbox | Payment | `internal/payments` |

**Offer and acceptance are both signed.** At checkout Chip In builds the canonical order (merchant, player, lines, unit prices, total, nonce) and puts its SHA-256 in the resource token: `checkout:pay amount:usd:3192 order:<hash>`. That resource token, signed by Chip In, is the offer. The auth token that comes back carries the same scope, signed after the player approved: the acceptance. Chip In charges only when the hash matches the order the cart holds, once per order, and Stripe's idempotency key is the order hash. The order behind a hash is viewable at `/orders/<hash>`.

**Tools ask for only the trust they need:**

| MCP tool | Token required |
|---|---|
| `catalog_search` | agent token |
| `cart_add`, `cart_view`, `cart_remove`, `checkout_quote` | person token (the player; directed `sub`) |
| `checkout_authorize`, `checkout_pay` | auth token for this order's amount and hash |

**Chip In's access server** (four-party, the person server federates to it) applies the shop's conditions: the request must name one order, under a per-order cap ($150) and the player's daily budget ($60), and an order is authorized once. Keycard is the intended home of these conditions (Cedar policy); see *Status*.

```
Agent → Chip In      catalog_search (agent token) → live UCP offers
Agent → Chip In      cart_add → 401 requirement=person-token
Agent → Hellō        person token  ⟵ player signs in (first time)
Agent → Chip In      cart_add (person token) ✓
Agent → Chip In      checkout_authorize → 401 requirement=auth-token, resource token (order hash, aud = Chip In AS)
Agent → Hellō        auth token request ⟵ player approves the order
Hellō → Chip In AS   federation: cap ✓ daily budget ✓ order once ✓ → auth token
Agent → Stripe       shared payment token, max_amount = order total
Agent → Chip In      checkout_pay (auth token + SPT) → PaymentIntent
```

## Run

Requires Go 1.26+.

```sh
go test ./...                         # end to end, offline (local person server, fake stores, fake Stripe)
go run ./cmd/chipin demo -pay=none    # whole flow locally, live UCP stores
go run ./cmd/chipin agent -shop https://chipin.aauth.tech   # the live demo; prints the Hellō sign-in link
```

Secrets via environment or `.env` (never committed): `STRIPE_SECRET_KEY` (sandbox only, live keys are refused), `CHIPIN_ENROLLMENT_SECRET` (authorizes agent installs at Chip In's agent provider).

`chipin serve` hosts everything on one origin: `/mcp`, `/.well-known/aauth-resource.json`, `/jwks`, `/revoke`, `/orders/{hash}` (shop); `/.well-known/aauth-agent.json`, `/ap/*` (agent provider); `/.well-known/aauth-access.json`, `/as/*` (access server); `/.well-known/ucp/chip-in-agent.json` (UCP agent profile); everything else from `public/`. Signing keys persist in `data/`. Deployment: `Dockerfile`, `deploy/docker-compose.yml`.

Offline rehearsal: `chipin record-catalog -out testdata/catalog.json`, then `-catalog-fixture testdata/catalog.json` (labeled "recorded fixture").

## Status

- Verified offline end to end, and against the live Stripe sandbox.
- **Open with Hellō:** whether it federates auth-token requests to a resource's access server, and how its consent shows the order behind the hash. If it does not federate, Chip In can address the resource token to Hellō (three-party) and apply its conditions before charging.
- **Keycard:** the access server's conditions are local code today; moving them to a Keycard Cedar policy is next.
- Chip In is the demo merchant of record: it charges in the Stripe sandbox and places no orders at the real stores. The SPT comes from Stripe's sandbox test helper, standing in for the agent's wallet.
