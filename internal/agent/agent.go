// Package agent is the shopping agent: it enrolls at Chip In's agent
// provider for an agent identity that names the person's server (Hellō),
// talks to Chip In's MCP server through aauth-go's Transport (which signs
// every request and answers each AAuth challenge), has the person approve
// each specific order at their person server, and pays with a Stripe shared
// payment token capped at the approved amount.
package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	aauth "github.com/aauth-dev/aauth-go"
	"github.com/aauth-dev/aauth-go/agentprovider"

	"github.com/gkedev/adelaide/internal/payments"
	"github.com/gkedev/adelaide/internal/shop"
	"github.com/gkedev/adelaide/internal/spend"
	"github.com/gkedev/adelaide/internal/trust"
	"github.com/gkedev/adelaide/internal/ucp"
)

// Config configures a shopping run.
type Config struct {
	ShopURL          string // Chip In (MCP at ShopURL + "/mcp")
	APURL            string // agent provider (Chip In's origin)
	PSURL            string // the person's server (https://person.hello.coop)
	EnrollmentSecret string
	// OnInteraction shows the person where to sign in or approve (URL and
	// code); nil logs it.
	OnInteraction func(url, code string)
	// Query, TargetBalls and BudgetCents describe the errand.
	Query       string
	TargetBalls int
	BudgetCents int64
	// TryOverBudget first attempts the best per-ball deal even when it
	// exceeds the budget, to show the person server refusing it.
	TryOverBudget bool
	// Wallet issues the shared payment token; nil pays with the shop's
	// test-card fallback.
	Wallet     *payments.Stripe
	HTTPClient *http.Client
	Insecure   bool
	Log        func(role, msg string)
}

// Result summarizes a run.
type Result struct {
	Agent   string      `json:"agent"`
	Mission string      `json:"mission_s256"`
	Order   *shop.Order `json:"order,omitempty"`
	Denials []string    `json:"denials,omitempty"`
}

// Run performs the errand end to end.
func Run(ctx context.Context, cfg Config) (*Result, error) {
	if cfg.Log == nil {
		cfg.Log = func(string, string) {}
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 60 * time.Second}
	}
	if cfg.Query == "" {
		cfg.Query = "tennis balls"
	}
	if cfg.TargetBalls <= 0 {
		cfg.TargetBalls = 24
	}
	if cfg.BudgetCents <= 0 {
		cfg.BudgetCents = 6000
	}
	log := func(msg string) { cfg.Log("Agent", msg) }

	// 1. An agent identity from AAuth.dev, bound to a key only this agent holds.
	key, err := aauth.GenerateKey(aauth.AlgEd25519)
	if err != nil {
		return nil, err
	}
	if cfg.APURL == "" {
		cfg.APURL = cfg.ShopURL
	}
	apc := &agentprovider.Client{BaseURL: cfg.APURL, HTTPClient: &http.Client{
		Timeout: 30 * time.Second, Transport: headerRT{trust.EnrollHeader, cfg.EnrollmentSecret, cfg.HTTPClient.Transport},
	}}
	issue := func(ctx context.Context) (*agentprovider.TokenResponse, error) { return apc.Issue(ctx, key, nil) }
	first, err := issue(ctx)
	if err != nil {
		return nil, fmt.Errorf("enroll at the agent provider: %w", err)
	}
	ac, err := aauth.VerifyAgentToken(ctx, first.AgentToken, aauth.VerifyAgentTokenOptions{Resolver: aauth.NewJWKSResolver(cfg.HTTPClient)})
	if err != nil {
		return nil, fmt.Errorf("verify agent token: %w", err)
	}
	id, err := aauth.ParseAgentIdentifier(ac.Subject)
	if err != nil {
		return nil, err
	}
	used := false
	agent, err := aauth.NewAgent(id, aauth.WithKey(key), aauth.WithTokenSource(apc.TokenSource(func(ctx context.Context) (*agentprovider.TokenResponse, error) {
		if !used {
			used = true
			return first, nil
		}
		return issue(ctx)
	})))
	if err != nil {
		return nil, err
	}
	res := &Result{Agent: id.String()}
	log(fmt.Sprintf("enrolled as %s (person server %s)", id.String(), cfg.PSURL))

	ps := aauth.NewPSClient(cfg.PSURL, agent)
	ps.HTTPClient = cfg.HTTPClient
	ps.PreferWaitSeconds = 30
	md, err := ps.Discover(ctx)
	if err != nil {
		return nil, fmt.Errorf("discover %s: %w", cfg.PSURL, err)
	}
	interact := cfg.OnInteraction
	if interact == nil {
		interact = func(u, code string) {
			cfg.Log("Person", fmt.Sprintf("sign in and approve at %s (code %s)", u, code))
		}
	}
	verify := aauth.TokenVerifyOptions{Resolver: aauth.NewJWKSResolver(cfg.HTTPClient), InsecureSkipIdentifierCheck: cfg.Insecure}
	newMCP := func(mission string) *mcpClient {
		tr := aauth.NewTransport(agent, ps)
		tr.Base = cfg.HTTPClient.Transport
		tr.ResourceVerify, tr.AuthVerify, tr.MissionS256 = verify, verify, mission
		tr.OnRequirement = func(r aauth.Requirement) {
			if r.URL != "" {
				interact(r.URL, r.Code)
			}
		}
		return &mcpClient{url: cfg.ShopURL + "/mcp", hc: &http.Client{Transport: tr, Timeout: 10 * time.Minute}}
	}

	// 2. Browse with only the agent token.
	browse := newMCP("")
	if _, err := browse.call(ctx, "initialize", map[string]any{
		"protocolVersion": "2025-06-18", "capabilities": map[string]any{},
		"clientInfo": map[string]any{"name": "chipin-agent", "version": "2.0.0"},
	}); err != nil {
		return nil, fmt.Errorf("initialize: %w", err)
	}
	var found struct {
		Source string            `json:"source"`
		Offers []ucp.Offer       `json:"offers"`
		Errors map[string]string `json:"store_errors"`
	}
	if err := browse.tool(ctx, "catalog_search", map[string]any{"query": cfg.Query}, &found); err != nil {
		return nil, fmt.Errorf("catalog_search: %w", err)
	}
	for store, e := range found.Errors {
		log(fmt.Sprintf("%s did not answer: %s", store, e))
	}
	best, value := choose(found.Offers, cfg.TargetBalls, cfg.BudgetCents)
	if best == nil {
		return nil, fmt.Errorf("no offer gives %d balls within %s (%d offers, %s)", cfg.TargetBalls, spend.Dollars(cfg.BudgetCents), len(found.Offers), found.Source)
	}
	log(fmt.Sprintf("%d offers (%s). Plan: %d × %s at %s = %s (%s/ball)",
		len(found.Offers), found.Source, best.qty, best.offer.Title, best.offer.Store,
		spend.Dollars(best.cost()), spend.Dollars(best.offer.PerBallCents())))

	// 3. A mission with a budget, when the person server supports missions.
	mission := ""
	if md.MissionEndpoint != "" {
		desc := fmt.Sprintf("# Tennis balls for Monday night doubles\n\nBuy at least %d pressurized tennis balls at Chip In, best price per ball.\n\n%s\n",
			cfg.TargetBalls, spend.BudgetLine(cfg.BudgetCents))
		prop := aauth.MissionProposal{Description: desc}
		if strings.HasPrefix(cfg.ShopURL, "https://") {
			prop.Resources = []string{cfg.ShopURL} // server identifiers only (§8.1)
		}
		m, err := ps.ProposeMission(ctx, prop)
		if err != nil {
			return nil, fmt.Errorf("propose mission: %w", err)
		}
		mission, res.Mission = m.S256, m.S256
		log(fmt.Sprintf("mission approved: %s… (budget %s)", m.S256[:12], spend.Dollars(cfg.BudgetCents)))
	} else {
		log("person server has no missions: each order is approved on its own")
	}
	shopping := newMCP(mission)

	pay := func(label string) (*shop.Order, error) {
		var quote struct {
			TotalCents int64  `json:"total_cents"`
			Scope      string `json:"checkout_scope"`
		}
		if err := shopping.tool(ctx, "checkout_quote", nil, &quote); err != nil {
			return nil, err
		}
		// Authorization first: the payment credential is minted only for an
		// amount AAuth.dev and Keycard have approved.
		log(fmt.Sprintf("checkout_authorize %s (%s)", spend.Dollars(quote.TotalCents), label))
		if err := shopping.tool(ctx, "checkout_authorize", nil, nil); err != nil {
			return nil, err
		}
		args := map[string]any{}
		if cfg.Wallet != nil {
			spt, err := cfg.Wallet.GrantTestSPT(ctx, quote.TotalCents, 10*time.Minute)
			if err != nil {
				return nil, fmt.Errorf("wallet: %w", err)
			}
			cfg.Log("Stripe", fmt.Sprintf("shared payment token %s… capped at %s, expires in 10 min", spt.ID[:12], spend.Dollars(spt.UsageLimits.MaxAmount)))
			args["payment_token"] = spt.ID
		}
		log(fmt.Sprintf("checkout_pay %s", spend.Dollars(quote.TotalCents)))
		var o shop.Order
		if err := shopping.tool(ctx, "checkout_pay", args, &o); err != nil {
			return nil, err
		}
		return &o, nil
	}

	// 3b. Optionally show the guardrail: the best per-ball deal, over budget.
	if cfg.TryOverBudget && value != nil && value.cost() > cfg.BudgetCents {
		log(fmt.Sprintf("trying the best per-ball deal anyway: %s at %s for %s (%s/ball)",
			value.offer.Title, value.offer.Store, spend.Dollars(value.cost()), spend.Dollars(value.offer.PerBallCents())))
		if err := shopping.tool(ctx, "cart_add", map[string]any{"offer_id": value.offer.ID, "quantity": value.qty}, nil); err != nil {
			return nil, fmt.Errorf("cart_add: %w", err)
		}
		if _, err := pay("over budget on purpose"); err != nil {
			res.Denials = append(res.Denials, err.Error())
			log("refused, as it should be: " + shortErr(err))
		} else {
			return nil, errors.New("an over-budget checkout was authorized")
		}
		if err := shopping.tool(ctx, "cart_remove", map[string]any{"offer_id": value.offer.ID}, nil); err != nil {
			return nil, fmt.Errorf("cart_remove: %w", err)
		}
	}

	// 4. The plan within budget: cart (person token), then pay (auth token).
	if err := shopping.tool(ctx, "cart_add", map[string]any{"offer_id": best.offer.ID, "quantity": best.qty}, nil); err != nil {
		return nil, fmt.Errorf("cart_add: %w", err)
	}
	order, err := pay("within budget")
	if err != nil {
		return nil, fmt.Errorf("checkout: %w", err)
	}
	res.Order = order
	log(fmt.Sprintf("paid: order %s, %s, Stripe %s %s", order.ID, spend.Dollars(order.TotalCents), orNone(order.PaymentIntent), order.PaymentStatus))

	// 5. Report to the person and close the mission, when there is one.
	if mission != "" {
		if err := ps.Audit(ctx, aauth.AuditRequest{
			MissionS256: mission, Action: "Purchase",
			Description: fmt.Sprintf("Bought %d × %s from Chip In for %s", best.qty, best.offer.Title, spend.Dollars(order.TotalCents)),
			Result:      map[string]any{"order_id": order.ID, "order_hash": order.OrderHash, "payment_intent": order.PaymentIntent, "total_cents": order.TotalCents},
		}); err != nil {
			return nil, fmt.Errorf("audit: %w", err)
		}
		summary := fmt.Sprintf("Bought %d balls for %s (order %s).", best.qty*best.offer.Balls, spend.Dollars(order.TotalCents), order.ID)
		if err := ps.CompleteMission(ctx, mission, summary); err != nil {
			return nil, fmt.Errorf("complete mission: %w", err)
		}
		log("mission complete")
	}
	return res, nil
}

// plan is a quantity of one offer.
type plan struct {
	offer ucp.Offer
	qty   int
}

func (p plan) cost() int64 { return p.offer.PriceCents * int64(p.qty) }

// excluded are listings that are not pressurized adult balls.
var excluded = []string{"foam", "starter", "red ", "orange", "green", "stage", "junior", "kids", "pressureless", "pickleball", "padel", "hopper", "basket", "cart"}

// choose returns the cheapest plan reaching target balls within budget, and
// the best per-ball plan regardless of budget.
func choose(offers []ucp.Offer, target int, budget int64) (best, value *plan) {
	var plans []plan
	for _, o := range offers {
		t := strings.ToLower(o.Title) + " "
		skip := !o.Available || o.Balls <= 0 || o.Currency != "usd" || o.PriceCents <= 0
		for _, w := range excluded {
			if strings.Contains(t, w) {
				skip = true
			}
		}
		if skip {
			continue
		}
		plans = append(plans, plan{offer: o, qty: (target + o.Balls - 1) / o.Balls})
	}
	sort.SliceStable(plans, func(i, j int) bool {
		if plans[i].cost() != plans[j].cost() {
			return plans[i].cost() < plans[j].cost()
		}
		return plans[i].offer.PerBallCents() < plans[j].offer.PerBallCents()
	})
	for i := range plans {
		if plans[i].cost() <= budget {
			best = &plans[i]
			break
		}
	}
	for i := range plans {
		if value == nil || plans[i].offer.PerBallCents() < value.offer.PerBallCents() {
			value = &plans[i]
		}
	}
	return best, value
}

// mcpClient speaks MCP Streamable HTTP (JSON responses) over an AAuth
// transport.
type mcpClient struct {
	url string
	hc  *http.Client
	id  int
}

func (c *mcpClient) call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	c.id++
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": c.id, "method": method, "params": params})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	res, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s %s", res.StatusCode, res.Header.Get("Signature-Error"), strings.TrimSpace(string(body)))
	}
	var rpc struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &rpc); err != nil {
		return nil, err
	}
	if rpc.Error != nil {
		return nil, errors.New(rpc.Error.Message)
	}
	return rpc.Result, nil
}

func (c *mcpClient) tool(ctx context.Context, name string, args map[string]any, out any) error {
	if args == nil {
		args = map[string]any{}
	}
	raw, err := c.call(ctx, "tools/call", map[string]any{"name": name, "arguments": args})
	if err != nil {
		return err
	}
	var r struct {
		IsError    bool            `json:"isError"`
		Structured json.RawMessage `json:"structuredContent"`
		Content    []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return err
	}
	if r.IsError {
		msg := "tool error"
		if len(r.Content) > 0 {
			msg = r.Content[0].Text
		}
		return errors.New(msg)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(r.Structured, out)
}

// headerRT adds one header to every request.
type headerRT struct {
	name, value string
	base        http.RoundTripper
}

func (h headerRT) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set(h.name, h.value)
	if h.base == nil {
		return http.DefaultTransport.RoundTrip(r)
	}
	return h.base.RoundTrip(r)
}

// shortErr drops the HTTP client's "Post URL:" wrapping from a refusal.
func shortErr(err error) string {
	s := err.Error()
	if i := strings.Index(s, "aauth: "); i >= 0 {
		return s[i+len("aauth: "):]
	}
	return s
}

func orNone(s string) string {
	if s == "" {
		return "(no payment)"
	}
	return s
}
