// Package agent is the shopping agent: it enrolls at ChipIn's agent
// provider for an agent identity that names the person's server (Hellō),
// talks to ChipIn's MCP server through aauth-go's Transport (which signs
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
	"github.com/gkedev/adelaide/internal/selection"
	"github.com/gkedev/adelaide/internal/shop"
	"github.com/gkedev/adelaide/internal/spend"
	"github.com/gkedev/adelaide/internal/trust"
	"github.com/gkedev/adelaide/internal/ucp"
)

// Config configures a shopping run.
type Config struct {
	ShopURL          string // ChipIn (MCP at ShopURL + "/mcp")
	APURL            string // agent provider (ChipIn's origin)
	PSURL            string // the person's server (https://person.hello.coop)
	EnrollmentSecret string
	// OnInteraction shows the person where to sign in or approve (URL and
	// code); nil logs it.
	OnInteraction func(url, code string)
	// Buy is the player's decision after reviewing the shortlist: "" ends
	// the run at the shortlist (default, nothing is bought), "best" buys
	// the recommended choice, "N" buys shortlist item N (1-based). Decide,
	// when set and Buy is "", asks the player instead.
	Buy    string
	Decide func(shortlist []Choice, recommended int) string
	// Packs, Brands and BudgetCents (the max cost) are the player's
	// choices: they become the selection mission Keycard enforces.
	Packs  []string
	Brands []string
	// Query, TargetBalls and BudgetCents describe the errand.
	Query       string
	TargetBalls int
	BudgetCents int64
	// TryOverBudget first attempts a tempting product outside the mission,
	// to show it refused at checkout. (Historically: the best per-ball deal even when it
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
	Agent   string `json:"agent"`
	Mission string `json:"mission_s256"`
	// Shortlist is the mission's result: the products across the stores
	// that meet the player's conditions, best price per ball first, each
	// with the quantity that covers the crew within the max cost.
	Shortlist   []Choice    `json:"shortlist"`
	Recommended int         `json:"recommended"` // index into Shortlist, -1 if none fits
	Order       *shop.Order `json:"order,omitempty"`
	Denials     []string    `json:"denials,omitempty"`
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
	ps.HTTPClient = &http.Client{Timeout: 10 * time.Minute, Transport: capabilityRT{
		ps: strings.TrimSuffix(cfg.PSURL, "/"), capabilities: []string{"interaction"}, agent: agent, base: cfg.HTTPClient.Transport,
	}}
	ps.PreferWaitSeconds = 30
	ps.OnRequirement = func(r aauth.Requirement) {
		if r.URL != "" && cfg.OnInteraction != nil {
			cfg.OnInteraction(r.URL, r.Code)
		} else if r.URL != "" {
			cfg.Log("Person", fmt.Sprintf("sign in and approve at %s (code %s)", r.URL, r.Code))
		}
	}
	if _, err := ps.Discover(ctx); err != nil {
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
	log(fmt.Sprintf("%d offers (%s)", len(found.Offers), found.Source))
	shopping := newMCP("")

	// 3. The player's choices become a selection mission across the stores.
	var prop struct {
		Mission selection.Mission `json:"mission"`
		Summary string            `json:"summary"`
		Source  string            `json:"source"`
	}
	if err := shopping.tool(ctx, "mission_propose", map[string]any{
		"packs": cfg.Packs, "brands": cfg.Brands, "max_cost_usd": float64(cfg.BudgetCents) / 100,
	}, &prop); err != nil {
		return nil, fmt.Errorf("mission_propose: %w", err)
	}
	log(fmt.Sprintf("mission proposed: %s → %d products (%s)", prop.Summary, len(prop.Mission.Products), prop.Source))
	for i, p := range prop.Mission.Products {
		if i == 6 {
			log(fmt.Sprintf("  … and %d more", len(prop.Mission.Products)-6))
			break
		}
		log(fmt.Sprintf("  %s · %s · %s", spend.Dollars(p.PriceCents), p.Store, p.Title))
	}

	// 4. The player approves the mission at their person server.
	var appr struct {
		EnforcedBy string `json:"enforced_by"`
	}
	if err := shopping.tool(ctx, "mission_approve", map[string]any{"mission_id": prop.Mission.ID}, &appr); err != nil {
		return nil, fmt.Errorf("mission_approve: %w", err)
	}
	res.Mission = prop.Mission.ID
	log("mission approved; enforced by " + appr.EnforcedBy)

	var inMission []ucp.Offer
	for _, p := range prop.Mission.Products {
		inMission = append(inMission, ucp.Offer{ID: p.OfferID, Store: p.Store, Title: p.Title, PriceCents: p.PriceCents,
			Currency: spend.Currency, Available: true, Balls: 3 * p.Cans, Cans: p.Cans, Brand: p.Brand})
	}
	res.Shortlist, res.Recommended = shortlist(inMission, cfg.TargetBalls, cfg.BudgetCents)
	log(fmt.Sprintf("shortlist: %d products meet %s", len(res.Shortlist), prop.Summary))
	for i, c := range res.Shortlist {
		mark := "  "
		if i == res.Recommended {
			mark = "★ "
		}
		log(fmt.Sprintf("%s%d. %s/ball · %d × %s at %s = %s", mark, i+1, spend.Dollars(c.PerBallCents), c.Quantity, c.Title, c.Store, spend.Dollars(c.TotalCents)))
	}
	value := offMission(found.Offers, prop.Mission.Criteria)

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

	// 4b. Optionally show the guardrail: a tempting product outside the mission.
	if cfg.TryOverBudget && value != nil {
		log(fmt.Sprintf("trying a product outside the mission: %s (%s, %s) at %s for %s",
			value.offer.Title, orDefault(value.offer.Brand, "unknown brand"), packName(value.offer.Cans), value.offer.Store, spend.Dollars(value.cost())))
		if err := shopping.tool(ctx, "cart_add", map[string]any{"offer_id": value.offer.ID, "quantity": value.qty}, nil); err != nil {
			return nil, fmt.Errorf("cart_add: %w", err)
		}
		if _, err := pay("outside the mission on purpose"); err != nil {
			res.Denials = append(res.Denials, err.Error())
			log("refused, as it should be: " + shortErr(err))
		} else {
			return nil, errors.New("a checkout outside the mission was authorized")
		}
		if err := shopping.tool(ctx, "cart_remove", map[string]any{"offer_id": value.offer.ID}, nil); err != nil {
			return nil, fmt.Errorf("cart_remove: %w", err)
		}
	}

	// 5. The player decides: review only (default), or buy one choice.
	decision := cfg.Buy
	if decision == "" && cfg.Decide != nil && len(res.Shortlist) > 0 {
		decision = cfg.Decide(res.Shortlist, res.Recommended)
	}
	pick, err := pickChoice(res.Shortlist, res.Recommended, decision)
	if err != nil {
		return nil, err
	}
	if pick == nil {
		log("mission complete: shortlist ready, nothing bought (run with -buy best or -buy N to purchase)")
		return res, nil
	}
	log(fmt.Sprintf("player chose to buy: %d × %s at %s = %s", pick.Quantity, pick.Title, pick.Store, spend.Dollars(pick.TotalCents)))
	if err := shopping.tool(ctx, "cart_add", map[string]any{"offer_id": pick.OfferID, "quantity": pick.Quantity}, nil); err != nil {
		return nil, fmt.Errorf("cart_add: %w", err)
	}
	order, err := pay("within the mission")
	if err != nil {
		return nil, fmt.Errorf("checkout: %w", err)
	}
	res.Order = order
	log(fmt.Sprintf("paid: order %s, %s, Stripe %s %s", order.ID, spend.Dollars(order.TotalCents), orNone(order.PaymentIntent), order.PaymentStatus))

	return res, nil
}

// Choice is one shortlisted product with the quantity the agent proposes.
type Choice struct {
	OfferID      string `json:"offer_id"`
	Store        string `json:"store"`
	Title        string `json:"title"`
	Brand        string `json:"brand"`
	Pack         string `json:"pack"`
	UnitCents    int64  `json:"unit_cents"`
	PerBallCents int64  `json:"per_ball_cents"`
	Quantity     int    `json:"quantity"`
	Balls        int    `json:"balls"`
	TotalCents   int64  `json:"total_cents"`
}

// shortlist ranks the mission's products by price per ball. Each gets the
// quantity covering target balls, capped by the max cost; the recommended
// choice is the cheapest per ball that covers the crew within the max.
func shortlist(products []ucp.Offer, target int, max int64) ([]Choice, int) {
	var out []Choice
	for _, o := range products {
		if o.Balls <= 0 || o.PriceCents <= 0 {
			continue
		}
		qty := (target + o.Balls - 1) / o.Balls
		if int64(qty)*o.PriceCents > max {
			qty = int(max / o.PriceCents)
		}
		if qty < 1 {
			continue
		}
		out = append(out, Choice{OfferID: o.ID, Store: o.Store, Title: o.Title, Brand: o.Brand, Pack: packName(o.Cans),
			UnitCents: o.PriceCents, PerBallCents: o.PerBallCents(), Quantity: qty, Balls: qty * o.Balls, TotalCents: int64(qty) * o.PriceCents})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].PerBallCents < out[j].PerBallCents })
	rec := -1
	for i, c := range out {
		if c.Balls >= target {
			rec = i
			break
		}
	}
	return out, rec
}

// pickChoice applies the player's decision: "" or "none" buys nothing.
func pickChoice(list []Choice, rec int, decision string) (*Choice, error) {
	switch d := strings.ToLower(strings.TrimSpace(decision)); d {
	case "", "none", "no", "skip":
		return nil, nil
	case "best", "yes":
		if rec < 0 {
			return nil, errors.New("no shortlisted product covers the crew within the max cost")
		}
		return &list[rec], nil
	default:
		var n int
		if _, err := fmt.Sscan(d, &n); err != nil || n < 1 || n > len(list) {
			return nil, fmt.Errorf("buy %q: choose best or 1..%d", decision, len(list))
		}
		return &list[n-1], nil
	}
}

// offMission is the most tempting pressurized product the catalog search
// found that the mission does not allow (cheapest per ball), one unit.
func offMission(offers []ucp.Offer, c selection.Criteria) *plan {
	any := selection.Criteria{Brands: selection.Brands, Packs: []string{"can", "12", "18", "24"}, MaxCostCents: 1 << 40}
	var best *plan
	for _, o := range offers {
		if !any.Matches(o) || c.Matches(o) || o.Balls <= 0 {
			continue
		}
		if best == nil || o.PerBallCents() < best.offer.PerBallCents() {
			best = &plan{offer: o, qty: 1}
		}
	}
	return best
}

func packName(cans int) string {
	switch p := selection.PackOf(cans); p {
	case "":
		return "not a can pack"
	case "can":
		return "single can"
	default:
		return p + "-can pack"
	}
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
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
