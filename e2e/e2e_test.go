// Package e2e runs the whole ChipIn flow in process: real aauth-go v0.2
// servers (AAuth.dev, Keycard), the ChipIn MCP resource, the agent, a fake
// UCP store, and a fake Stripe that enforces shared payment token caps.
package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gkedev/adelaide/internal/agent"
	"github.com/gkedev/adelaide/internal/localps"
	"github.com/gkedev/adelaide/internal/payments"
	"github.com/gkedev/adelaide/internal/shop"
	"github.com/gkedev/adelaide/internal/trust"
	"github.com/gkedev/adelaide/internal/ucp"
)

// server starts an httptest server whose handler is set later, so URLs
// exist before the handlers that need them.
func server(t *testing.T) (*httptest.Server, *http.Handler) {
	var h http.Handler = http.NotFoundHandler()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) }))
	t.Cleanup(s.Close)
	return s, &h
}

// fakeStore answers UCP search_catalog with fixed products.
func fakeStore(t *testing.T, products ...map[string]any) string {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Params struct {
				Name      string `json:"name"`
				Arguments struct {
					Meta map[string]map[string]string `json:"meta"`
				} `json:"arguments"`
			} `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Params.Name != "search_catalog" || req.Params.Arguments.Meta["ucp-agent"]["profile"] == "" {
			http.Error(w, "bad UCP call", http.StatusBadRequest)
			return
		}
		b, _ := json.Marshal(map[string]any{"products": products})
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1,
			"result": map[string]any{"content": []map[string]any{{"type": "text", "text": string(b)}}}})
	}))
	t.Cleanup(s.Close)
	return s.URL
}

func product(id, title string, cents int64) map[string]any {
	return map[string]any{
		"id": id, "title": title, "url": "https://store.example/" + id,
		"price_range": map[string]any{"min": map[string]any{"amount": cents, "currency": "USD"}},
		"variants": []map[string]any{{"id": id + "-v", "title": "Default Title",
			"price": map[string]any{"amount": cents, "currency": "USD"}, "availability": map[string]any{"available": true}}},
	}
}

// fakeStripe grants SPTs and accepts PaymentIntents within an SPT's cap,
// once per token.
type fakeStripe struct {
	mu       sync.Mutex
	caps     map[string]int64
	used     map[string]bool
	payments []map[string]string
}

func (f *fakeStripe) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	f.mu.Lock()
	defer f.mu.Unlock()
	fail := func(msg string) {
		w.WriteHeader(http.StatusPaymentRequired)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"type": "card_error", "message": msg}})
	}
	switch r.URL.Path {
	case "/v1/test_helpers/shared_payment/granted_tokens":
		id := fmt.Sprintf("spt_test%04d", len(f.caps)+1)
		n, _ := strconv.ParseInt(r.Form.Get("usage_limits[max_amount]"), 10, 64)
		f.caps[id] = n
		_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "usage_limits": map[string]any{"currency": "usd", "max_amount": n}})
	case "/v1/payment_intents":
		amount, _ := strconv.ParseInt(r.Form.Get("amount"), 10, 64)
		if spt := r.Form.Get("payment_method_data[shared_payment_granted_token]"); spt != "" {
			if f.used[spt] {
				fail("token already used")
				return
			}
			if amount > f.caps[spt] {
				fail("amount above the token's max_amount")
				return
			}
			f.used[spt] = true
		}
		p := map[string]string{"amount": r.Form.Get("amount"), "spt": r.Form.Get("payment_method_data[shared_payment_granted_token]"),
			"mission": r.Form.Get("metadata[mission_s256]"), "idem": r.Header.Get("Idempotency-Key")}
		f.payments = append(f.payments, p)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": fmt.Sprintf("pi_test%d", len(f.payments)), "status": "succeeded", "amount": amount, "currency": "usd"})
	default:
		http.NotFound(w, r)
	}
}

type deployment struct {
	shopURL, psURL string
	shop           *shop.Shop
	stripe         *fakeStripe
	wallet         *payments.Stripe
	trace          *strings.Builder
	log            func(string, string)
}

func deploy(t *testing.T, maxOrderCents int64) *deployment { return deployWith(t, maxOrderCents, nil) }

// deployWith starts ChipIn (shop, agent provider, access server on one
// origin) and a local person server standing in for Hellō. live, when set,
// replaces the fake Stripe.
func deployWith(t *testing.T, maxOrderCents int64, live *payments.Stripe) *deployment {
	t.Helper()
	trace := &strings.Builder{}
	var mu sync.Mutex
	log := func(role, msg string) {
		mu.Lock()
		defer mu.Unlock()
		fmt.Fprintf(trace, "%-10s %s\n", role, msg)
	}
	chipSrv, chipH := server(t)
	psSrv, psH := server(t)
	hc := &http.Client{Timeout: 10 * time.Second}

	ps, err := localps.New(psSrv.URL, "G", hc, log)
	if err != nil {
		t.Fatal(err)
	}
	psMux := http.NewServeMux()
	ps.Register(psMux)
	*psH = psMux

	var sh *shop.Shop
	roles, err := trust.New(trust.Config{
		Authorize: func(scope, ps, sub string) error { return sh.Authorize(scope, ps, sub) },
		Issuer:    chipSrv.URL, PS: psSrv.URL, AgentDomain: "agents.chipin.localhost",
		MaxOrderCents: maxOrderCents, EnrollmentSecret: "install-7",
		HTTPClient: hc, Insecure: true, Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}

	te := fakeStore(t,
		product("te1", "Penn Championship Extra Duty 12 Cans", 5495),
		product("te2", "Championship Extra Duty Tennis Ball Case", 11995), // Penn (product line), 24 cans, over $60
		product("te3", "Championship Extra Duty Tennis Ball Can", 399))    // a single can: never a choice
	hb := fakeStore(t,
		product("hb1", "Dunlop ATP Championship Extra Duty 12 Pack Tennis Ball Case", 4995), // 12 cans, cheap, but Dunlop
		product("hb2", "Wilson Starter Foam Ball 6 Pack", 2395))
	catalog := &ucp.Client{Profile: "https://demo.example/ucp-agent.json", Stores: []ucp.Store{
		{Name: "Tennis Express", Domain: "te.example", Code: "te", Endpoint: te},
		{Name: "Holabird Sports", Domain: "hb.example", Code: "hb", Endpoint: hb},
	}}

	fs := &fakeStripe{caps: map[string]int64{}, used: map[string]bool{}}
	stripeSrv := httptest.NewServer(fs)
	t.Cleanup(stripeSrv.Close)
	st := &payments.Stripe{Key: "sk_test_fake", BaseURL: stripeSrv.URL}
	if live != nil {
		st = live
	}
	sh, err = shop.New(shop.Config{
		URL: chipSrv.URL, AccessServer: chipSrv.URL, TrustedIssuers: []string{psSrv.URL, chipSrv.URL},
		Catalog: catalog, Stripe: st, HTTPClient: hc, Insecure: true, Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	roles.Register(mux)
	sh.Register(mux)
	*chipH = mux
	return &deployment{shopURL: chipSrv.URL, psURL: psSrv.URL, shop: sh, stripe: fs, wallet: st, trace: trace, log: log}
}

func (d *deployment) run(t *testing.T, mutate func(*agent.Config)) (*agent.Result, error) {
	cfg := agent.Config{
		ShopURL: d.shopURL, APURL: d.shopURL, PSURL: d.psURL, EnrollmentSecret: "install-7",
		TargetBalls: 24, BudgetCents: 6000, TryOverBudget: true, Wallet: d.wallet,
		Packs: []string{"12", "24"}, Brands: []string{"Penn"}, Buy: "best",
		HTTPClient: &http.Client{Timeout: 20 * time.Second}, Insecure: true, Log: d.log,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := agent.Run(ctx, cfg)
	t.Log("\n" + d.trace.String())
	return res, err
}

func TestSelectionMission(t *testing.T) {
	d := deploy(t, 15000)
	res, err := d.run(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The player chose Penn, 12- or 24-packs, up to $60. The Dunlop 12-pack
	// is cheaper per ball but outside the mission: refused.
	if len(res.Denials) != 1 || !strings.Contains(res.Denials[0], "outside your mission") || !strings.Contains(res.Denials[0], "Dunlop") {
		t.Fatalf("denials %q", res.Denials)
	}
	// One Penn 12-pack, $54.95 (the Penn case, $119.95, is over the max cost).
	o := res.Order
	if o == nil || o.TotalCents != 5495 || o.PaidWith != "shared_payment_token" || o.PaymentStatus != "succeeded" || o.OrderHash == "" {
		t.Fatalf("order %+v", o)
	}
	if len(d.stripe.payments) != 1 || d.stripe.payments[0]["idem"] != o.OrderHash || len(d.stripe.caps) != 1 {
		t.Fatalf("stripe payments %v caps %v", d.stripe.payments, d.stripe.caps)
	}
	for _, want := range []string{
		"selection proposed: Penn · 12-pack, 24-pack · up to $60.00 → 1 of",
		"G approves", // the mission, at the person server
		"selection " + res.Mission[:10],
		"DENY (local mission rules) Dunlop ATP Championship Extra Duty 12 Pack",
		"ALLOW $54.95 for order " + o.OrderHash[:10],
	} {
		if !strings.Contains(d.trace.String(), want) {
			t.Errorf("trace lacks %q", want)
		}
	}
}

// TestShortlistOnly: by default the mission ends at the shortlist and
// nothing is bought.
func TestShortlistOnly(t *testing.T) {
	d := deploy(t, 15000)
	res, err := d.run(t, func(c *agent.Config) { c.Buy = "" })
	if err != nil {
		t.Fatal(err)
	}
	if res.Order != nil || len(d.stripe.payments) != 0 || len(d.stripe.caps) != 0 {
		t.Fatalf("bought without the player's decision: %+v", res.Order)
	}
	if len(res.Shortlist) != 1 || res.Recommended != 0 || res.Shortlist[0].Quantity != 1 || res.Shortlist[0].TotalCents != 5495 {
		t.Fatalf("shortlist %+v rec %d", res.Shortlist, res.Recommended)
	}
	if !strings.Contains(d.trace.String(), "nothing bought") {
		t.Error("trace does not say nothing was bought")
	}
}

// TestAuthorizeOnly: the order is approved (Keycard rules ALLOW, auth
// token issued) and nothing is paid.
func TestAuthorizeOnly(t *testing.T) {
	d := deploy(t, 15000)
	res, err := d.run(t, func(c *agent.Config) { c.AuthorizeOnly = true; c.TryOverBudget = false })
	if err != nil {
		t.Fatal(err)
	}
	if res.Order != nil || len(d.stripe.payments) != 0 || len(d.stripe.caps) != 0 {
		t.Fatalf("paid in an authorize-only run: %+v", res.Order)
	}
	if !strings.Contains(d.trace.String(), "ALLOW $54.95 for order") || !strings.Contains(d.trace.String(), "payment not made") {
		t.Errorf("trace lacks the authorization:\n%s", d.trace.String())
	}
}

// TestPackSizes: listings map to the pack choices, single cans to none.
func TestPackSizes(t *testing.T) {
	for title, want := range map[string]int{
		"Penn Championship Extra Duty 12 Cans": 12, "ATP Championship Extra Duty 12 Pack Tennis Ball Case": 12,
		"Slazenger Wimbledon 4 Tennis Ball 18 Can Case": 18, "Championship Extra Duty Tennis Ball Case": 24,
		"Championship Extra Duty Tennis Ball Can": 1, "Wilson Starter Foam Ball 6 Pack": 0, "Penn CONTROL+ Bag of 12": 0,
	} {
		if got := ucp.CansInTitle(title); got != want {
			t.Errorf("%q: %d cans, want %d", title, got, want)
		}
	}
}

// TestNoMissionNoCheckout: without an approved selection, nothing can be paid.
func TestNoMissionNoCheckout(t *testing.T) {
	d := deploy(t, 15000)
	_, err := d.run(t, func(c *agent.Config) { c.Brands = []string{"Tecnifibre"} })
	if err == nil || !strings.Contains(err.Error(), "no products match") {
		t.Fatalf("err %v", err)
	}
	if len(d.stripe.payments) != 0 {
		t.Fatal("charged without a mission")
	}
}

// TestApprovalBindsTheOrder: an auth token approved for one order does not
// pay for another with the same total.
func TestApprovalBindsTheOrder(t *testing.T) {
	a := &shop.Offer{Merchant: "m", Shopper: "s", TotalCents: 100, Currency: "usd", Nonce: "1",
		Items: []shop.OfferLine{{OfferID: "x", UnitCents: 100, Quantity: 1}}}
	b := *a
	b.Items = []shop.OfferLine{{OfferID: "y", UnitCents: 100, Quantity: 1}}
	if a.Hash() == b.Hash() {
		t.Fatal("different orders with the same total share a hash")
	}
	c := *a
	if a.Hash() != c.Hash() {
		t.Fatal("hash is not deterministic")
	}
}

func TestPerOrderCap(t *testing.T) {
	d := deploy(t, 2000) // ChipIn caps orders at $20
	_, err := d.run(t, func(c *agent.Config) { c.TryOverBudget = false })
	if err == nil || !strings.Contains(err.Error(), "need a human at ChipIn") {
		t.Fatalf("err %v", err)
	}
	if len(d.stripe.payments) != 0 {
		t.Fatalf("charged despite the cap: %v", d.stripe.payments)
	}
}

func TestTestCardFallback(t *testing.T) {
	d := deploy(t, 15000)
	res, err := d.run(t, func(c *agent.Config) { c.Wallet = nil; c.TryOverBudget = false })
	if err != nil {
		t.Fatal(err)
	}
	if res.Order.PaidWith != "test_card" || d.stripe.payments[0]["spt"] != "" {
		t.Fatalf("order %+v payments %v", res.Order, d.stripe.payments)
	}
}

// TestLiveStripeSandbox runs the purchase against the real Stripe sandbox
// (shared payment token, then PaymentIntent). It needs CHIPIN_LIVE_STRIPE=1
// and STRIPE_SECRET_KEY set to a sandbox key.
func TestLiveStripeSandbox(t *testing.T) {
	if os.Getenv("CHIPIN_LIVE_STRIPE") != "1" {
		t.Skip("set CHIPIN_LIVE_STRIPE=1 and STRIPE_SECRET_KEY to charge the Stripe sandbox")
	}
	live, err := payments.New(os.Getenv("STRIPE_SECRET_KEY"))
	if err != nil {
		t.Fatal(err)
	}
	d := deployWith(t, 15000, live)
	res, err := d.run(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	o := res.Order
	if o.PaidWith != "shared_payment_token" || o.PaymentStatus != "succeeded" || !strings.HasPrefix(o.PaymentIntent, "pi_") {
		t.Fatalf("order %+v", o)
	}
	t.Logf("Stripe sandbox payment: %s", o.DashboardURL)
}
