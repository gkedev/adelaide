// Package shop is ChipIn, the demo merchant: an MCP server (Streamable
// HTTP, JSON responses) protected with AAuth draft -11 as a resource.
//
// Each tool asks for only as much trust as it needs (§6):
//
//	catalog_search                      agent token  (who is the agent)
//	cart_add, cart_view, cart_remove,
//	checkout_quote                      person token (whose cart; directed sub)
//	checkout_authorize, checkout_pay    auth token from Keycard for exactly
//	                                    the cart total (scope checkout:pay
//	                                    amount:usd:N); pay then charges Stripe
//
// checkout_authorize lets an agent obtain the authorization before it
// mints a payment credential, so a refused checkout never creates one.
//
// The catalog is live: ChipIn sources offers from real retailers over UCP
// (see package ucp). ChipIn itself is the demo merchant of record; it
// charges in the Stripe sandbox and does not place orders at the stores.
package shop

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	aauth "github.com/aauth-dev/aauth-go"

	"github.com/gkedev/adelaide/internal/keycard"
	"github.com/gkedev/adelaide/internal/payments"
	"github.com/gkedev/adelaide/internal/selection"
	"github.com/gkedev/adelaide/internal/spend"
	"github.com/gkedev/adelaide/internal/ucp"
)

//go:embed static/ucp-agent.json
var ucpAgentProfile []byte

// UCPProfilePath is where the shop serves its UCP agent profile.
const UCPProfilePath = "/.well-known/ucp/chip-in-agent.json"

// Config configures the shop.
type Config struct {
	// Key signs resource tokens (generated when nil).
	Key crypto.Signer
	// URL is the shop's server identifier (the resource, iss of its
	// resource tokens).
	URL string
	// AccessServer is Keycard's URL: the aud of ChipIn's resource tokens.
	AccessServer string
	// TrustedIssuers are the person and access servers whose tokens the
	// shop accepts (§9.4.3.2: a valid signature alone is not trust).
	TrustedIssuers []string
	// Catalog searches the stores.
	Catalog *ucp.Client
	// Selections holds selection missions (created when nil).
	Selections *selection.Registry
	// Keycard, when set, enforces each player's mission: approving a
	// selection publishes its Cedar policy, and every order line is
	// evaluated by Keycard. Without it the same rules are checked locally.
	Keycard *keycard.Client
	// Stripe charges payments; nil runs checkout without charging
	// (reported as "payment: skipped").
	Stripe *payments.Stripe
	// HTTPClient is used for key discovery.
	HTTPClient *http.Client
	// Insecure accepts http://localhost identifiers (local demo only).
	Insecure bool
	// Log reports each step for the demo trace.
	Log func(role, msg string)
}

// Shop is the ChipIn resource.
type Shop struct {
	cfg      Config
	key      crypto.Signer
	kid      string
	jwks     aauth.JWKS
	resolver aauth.KeyResolver
	trusted  map[string]bool

	mu      sync.Mutex
	offers  map[string]ucp.Offer // offer id → last seen offer
	carts   map[string]*cart     // shopper → cart
	orders  []Order
	revoked map[[2]string]bool // (iss, jti) revoked at the shop
	pending map[string]*Offer  // order hash → the order offered in a resource token
	paid    map[string]bool    // order hashes already paid
	spent   map[string]int64   // selection mission id → cents paid under it
}

type cart struct {
	Items []Item
	Nonce string // changes whenever the cart does, so every order is unique
}

// Offer is the merchant's canonical statement of one purchase. Its SHA-256
// is carried in the resource token's scope (the signed offer) and comes back
// in the auth token (the person's signed acceptance of exactly this order).
type Offer struct {
	Merchant   string      `json:"merchant"`
	Shopper    string      `json:"shopper"`
	Items      []OfferLine `json:"items"`
	TotalCents int64       `json:"total_cents"`
	Currency   string      `json:"currency"`
	Selection  string      `json:"selection"` // the approved selection mission it falls under
	Nonce      string      `json:"nonce"`
}

// OfferLine is one line of an offer.
type OfferLine struct {
	OfferID   string `json:"offer_id"`
	Store     string `json:"store"`
	Title     string `json:"title"`
	VariantID string `json:"variant_id"`
	Brand     string `json:"brand"`
	Cans      int    `json:"cans"`
	UnitCents int64  `json:"unit_cents"`
	Quantity  int    `json:"quantity"`
}

// Hash is the unpadded base64url SHA-256 of the offer's JSON.
func (o *Offer) Hash() string {
	b, _ := json.Marshal(o)
	sum := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Item is a cart line.
type Item struct {
	Offer    ucp.Offer `json:"offer"`
	Quantity int       `json:"quantity"`
}

// Order is a paid checkout.
type Order struct {
	ID            string `json:"id"`
	Shopper       string `json:"shopper"`
	Items         []Item `json:"items"`
	TotalCents    int64  `json:"total_cents"`
	OrderHash     string `json:"order_hash"`
	Mission       string `json:"mission_s256,omitempty"`
	AuthorizedBy  string `json:"authorized_by"` // the auth token's issuer
	PaymentIntent string `json:"payment_intent,omitempty"`
	PaymentStatus string `json:"payment_status"`
	PaidWith      string `json:"paid_with,omitempty"` // "shared_payment_token" or "test_card"
	DashboardURL  string `json:"dashboard_url,omitempty"`
	Fulfillment   string `json:"fulfillment"`
	CreatedAt     string `json:"created_at"`
}

// New builds the shop with a fresh resource signing key.
func New(cfg Config) (*Shop, error) {
	if cfg.URL == "" || cfg.AccessServer == "" || cfg.Catalog == nil {
		return nil, errors.New("shop: URL, AccessServer and Catalog are required")
	}
	if cfg.Log == nil {
		cfg.Log = func(string, string) {}
	}
	key := cfg.Key
	if key == nil {
		var err error
		if key, err = aauth.GenerateKey(aauth.AlgEd25519); err != nil {
			return nil, err
		}
	}
	jwk, err := aauth.NewJWK(key.Public())
	if err != nil {
		return nil, err
	}
	s := &Shop{
		cfg: cfg, key: key, kid: jwk.Kid, jwks: aauth.JWKS{Keys: []aauth.JWK{jwk}},
		resolver: aauth.NewJWKSResolver(cfg.HTTPClient),
		trusted:  map[string]bool{},
		offers:   map[string]ucp.Offer{}, carts: map[string]*cart{}, revoked: map[[2]string]bool{},
		pending: map[string]*Offer{}, paid: map[string]bool{}, spent: map[string]int64{},
	}
	if s.cfg.Selections == nil {
		s.cfg.Selections = selection.NewRegistry()
	}
	for _, iss := range cfg.TrustedIssuers {
		s.trusted[iss] = true
	}
	return s, nil
}

// Orders returns the orders placed so far.
func (s *Shop) Orders() []Order {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Order(nil), s.orders...)
}

// Register adds the shop's routes to mux: resource metadata, JWKS,
// revocation, the MCP endpoint, the UCP agent profile, and order pages.
func (s *Shop) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/"+aauth.WellKnownResource, s.serveMetadata)
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, s.jwks) })
	mux.HandleFunc("POST /revoke", s.serveRevoke)
	mux.HandleFunc("/mcp", s.serveMCP)
	mux.HandleFunc("GET "+UCPProfilePath, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = w.Write(ucpAgentProfile)
	})
	mux.HandleFunc("GET /orders/{hash}", s.serveOrder)
	mux.HandleFunc("GET /missions/{id}", s.serveMission)
}

// serveMission shows a selection mission: the choices and the products
// they authorize.
func (s *Shop) serveMission(w http.ResponseWriter, r *http.Request) {
	m, ok := s.cfg.Selections.Get(r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"mission": m, "summary": m.Criteria.Summary()})
}

// Authorize is ChipIn's check, for its access server, that a scope the
// person (ps, sub) approved matches what ChipIn offered them: a selection
// mission they proposed, or an order that falls entirely within their
// approved selection and its max cost.
func (s *Shop) Authorize(scope, ps, sub string) error {
	shopper := ps + "|" + sub
	if selection.IsApproval(scope) {
		m, ok := s.cfg.Selections.Get(selection.FromScope(scope))
		if !ok || m.Shopper != shopper {
			return errors.New("no such selection for this person")
		}
		return nil
	}
	amount, ok := spend.AmountFromScope(scope)
	if !ok {
		return nil
	}
	s.mu.Lock()
	o := s.pending[spend.OrderFromScope(scope)]
	s.mu.Unlock()
	if o == nil || o.Shopper != shopper || o.TotalCents != amount {
		return errors.New("ChipIn made no such offer to this person")
	}
	m, ok := s.cfg.Selections.Get(o.Selection)
	if !ok || m.Status != "approved" || m.Shopper != shopper || selection.FromScope(scope) != m.ID {
		return errors.New("the order is not under an approved selection")
	}
	s.mu.Lock()
	spent := s.spent[m.ID]
	s.mu.Unlock()
	return s.enforceMission(m, o, spent+amount)
}

// enforceMission applies the player's choices to every order line: brand,
// pack size, and the mission's total spending against its max cost. Keycard
// decides when configured; otherwise the same rules run here.
func (s *Shop) enforceMission(m *selection.Mission, o *Offer, totalCents int64) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, l := range o.Items {
		pack := selection.PackOf(l.Cans)
		desc := fmt.Sprintf("%s (brand %s, pack %s, mission total %s)", l.Title, orDefault(l.Brand, "unknown"), orDefault(pack, "not a can pack"), spend.Dollars(totalCents))
		if s.cfg.Keycard != nil && m.KeycardPolicyID != "" {
			d, err := s.cfg.Keycard.Evaluate(ctx, &keycard.Policy{ID: m.KeycardPolicyID}, keycard.Scopes(m.ID, keycard.Line{Brand: l.Brand, Pack: pack}, totalCents))
			if err != nil {
				return fmt.Errorf("Keycard unavailable: %w", err)
			}
			if !d.Allow {
				s.cfg.Log("Keycard", fmt.Sprintf("DENY %s: outside mission policy %s", desc, m.KeycardPolicyName))
				return fmt.Errorf("Keycard denied: %s is outside your mission (%s)", desc, m.Criteria.Summary())
			}
			s.cfg.Log("Keycard", fmt.Sprintf("ALLOW %s under %s", desc, m.KeycardPolicyName))
			continue
		}
		c := m.Criteria
		if !slices.Contains(c.Brands, l.Brand) || !slices.Contains(c.Packs, pack) || totalCents > c.MaxCostCents {
			s.cfg.Log("ChipIn", "DENY (local mission rules) "+desc)
			return fmt.Errorf("outside your mission: %s (%s)", desc, c.Summary())
		}
	}
	return nil
}

// ServeHTTP serves the shop's routes alone (tests, single-role use).
func (s *Shop) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	mux := http.NewServeMux()
	s.Register(mux)
	mux.ServeHTTP(w, r)
}

// serveOrder shows an offered order, so a person approving it can see
// exactly what the hash in the request stands for.
func (s *Shop) serveOrder(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	o := s.pending[r.PathValue("hash")]
	s.mu.Unlock()
	if o == nil {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"order_hash": o.Hash(), "order": o, "total": spend.Dollars(o.TotalCents)})
}

func (s *Shop) serveMetadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, aauth.ResourceMetadata{
		ServerMetadata:     aauth.ServerMetadata{Issuer: s.cfg.URL, JWKSURI: s.cfg.URL + "/jwks"},
		AccessMode:         aauth.AccessModeAuthToken,
		RevocationEndpoint: s.cfg.URL + "/revoke",
		ScopeDescriptions: map[string]string{
			spend.ScopeCheckout: "Pay ChipIn for one specific order: the amount and order named in the request. See " + s.cfg.URL + "/orders/{order} for its items.",
		},
	})
}

// serveRevoke accepts revocations from the issuer of a token presented
// here (§11.12): the PS or Keycard.
func (s *Shop) serveRevoke(w http.ResponseWriter, r *http.Request) {
	caller, err := aauth.VerifyServerRequest(r.Context(), r, aauth.VerifyServerOptions{
		Resolver: s.resolver, InsecureSkipIdentifierCheck: s.cfg.Insecure,
		Signature: aauth.RequestVerifyOptions{RequireBodyCoverage: true},
	})
	if err != nil {
		aauth.WriteSignatureFailure(w, err)
		return
	}
	rr, err := aauth.ParseRevocationRequest(r)
	if err != nil {
		aauth.WriteProblem(w, http.StatusBadRequest, aauth.ErrCodeInvalidRequest, err.Error())
		return
	}
	s.mu.Lock()
	s.revoked[[2]string{caller.ID, rr.JTI}] = true
	s.mu.Unlock()
	s.cfg.Log("ChipIn", fmt.Sprintf("token %s… revoked by %s", truncate(rr.JTI, 8), caller.ID))
	w.WriteHeader(http.StatusOK)
}

// tier is how much a request must prove.
type tier int

const (
	tierAgent tier = iota
	tierPerson
	tierAuth
)

func toolTier(method, tool string) tier {
	if method != "tools/call" {
		return tierAgent
	}
	switch tool {
	case "cart_add", "cart_view", "cart_remove", "checkout_quote", "mission_propose":
		return tierPerson
	case "checkout_authorize", "checkout_pay", "mission_approve":
		return tierAuth
	}
	return tierAgent
}

// caller is who a verified request comes from.
type caller struct {
	Agent   string // agent identifier, when an agent token was presented
	Shopper string // "iss|sub" of the person token or "ps|sub" of the auth token
	Auth    *aauth.AuthClaims
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	} `json:"params"`
}

func (s *Shop) serveMCP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "MCP Streamable HTTP: POST JSON-RPC here", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	var req rpcRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeRPCError(w, nil, -32700, "parse error")
		return
	}
	need := toolTier(req.Method, req.Params.Name)
	c, ok := s.authenticate(w, r, need, req.Params.Name, req.Params.Arguments)
	if !ok {
		return
	}
	if strings.HasPrefix(req.Method, "notifications/") {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	var result any
	switch req.Method {
	case "initialize":
		result = map[string]any{
			"protocolVersion": "2025-06-18",
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "chip-in", "title": "ChipIn", "version": "2.0.0"},
			"instructions":    "Live tennis ball offers from Tennis Express and Holabird Sports. Payments need an AAuth mission with a budget.",
		}
	case "ping":
		result = map[string]any{}
	case "tools/list":
		result = map[string]any{"tools": toolList()}
	case "tools/call":
		out, err := s.callTool(r.Context(), c, req.Params.Name, req.Params.Arguments)
		result = toolResult(out, err)
	default:
		writeRPCError(w, req.ID, -32601, "method not found: "+req.Method)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
}

// authenticate verifies the presented token and, when it proves less than
// need, answers the AAuth challenge for the next token (§6.4, §6.5).
func (s *Shop) authenticate(w http.ResponseWriter, r *http.Request, need tier, tool string, args json.RawMessage) (*caller, bool) {
	ctx := r.Context()
	tok, err := aauth.ParseSignatureKey(r)
	if err != nil {
		aauth.WriteSignatureFailure(w, err)
		return nil, false
	}
	typ, err := aauth.TokenType(tok)
	if err != nil {
		aauth.WriteSignatureFailure(w, err)
		return nil, false
	}
	verify := aauth.TokenVerifyOptions{Resolver: s.resolver, InsecureSkipIdentifierCheck: s.cfg.Insecure}
	switch typ {
	case aauth.TypAgent:
		ac, err := aauth.VerifyAndExtractAgent(ctx, r, aauth.VerifyAgentTokenOptions{Resolver: s.resolver})
		if err != nil {
			aauth.WriteSignatureFailure(w, err)
			return nil, false
		}
		if need > tierAgent {
			s.cfg.Log("ChipIn", fmt.Sprintf("%s needs the person behind %s → requirement=person-token", tool, ac.Subject))
			aauth.ChallengePersonToken(w)
			return nil, false
		}
		return &caller{Agent: ac.Subject}, true

	case aauth.TypPerson:
		pc, err := aauth.VerifyAndExtractPerson(ctx, r, s.cfg.URL, verify)
		if err == nil && !s.trusted[pc.Issuer] {
			err = fmt.Errorf("%w: %s is not a person server ChipIn trusts", aauth.ErrInvalidToken, pc.Issuer)
		}
		if err == nil && s.isRevoked(pc.Issuer, pc.ID) {
			err = aauth.ErrRevoked
		}
		if err != nil {
			aauth.WriteSignatureFailure(w, err)
			return nil, false
		}
		c := &caller{Shopper: pc.Issuer + "|" + pc.Subject}
		if need == tierAuth {
			s.challengeFor(w, tool, args, c.Shopper, pc)
			return nil, false
		}
		return c, true

	case aauth.TypAuth:
		ac, err := aauth.VerifyAndExtractAuth(ctx, r, s.cfg.URL, aauth.AuthTokenVerifyOptions{
			TokenVerifyOptions: verify,
			CheckSubject: func(_ context.Context, iss, _ string) error {
				if !s.trusted[iss] {
					return fmt.Errorf("%w: %s is not an issuer ChipIn trusts", aauth.ErrInvalidToken, iss)
				}
				return nil
			},
		})
		if err == nil && s.isRevoked(ac.Issuer, ac.ID) {
			err = aauth.ErrRevoked
		}
		if err != nil {
			aauth.WriteSignatureFailure(w, err)
			return nil, false
		}
		c := &caller{Shopper: ac.PS + "|" + ac.Subject, Auth: ac}
		if need == tierAuth && !s.grants(tool, args, c.Shopper, ac.Scope) {
			// This token approved something else (another order, another
			// selection): step up for what this call needs.
			s.challengeFor(w, tool, args, c.Shopper, ac)
			return nil, false
		}
		return c, true
	}
	aauth.ChallengeAgentToken(w)
	return nil, false
}

// grants reports whether an auth token's scope covers this call.
func (s *Shop) grants(tool string, args json.RawMessage, shopper, scope string) bool {
	if tool == "mission_approve" {
		return selection.IsApproval(scope) && selection.FromScope(scope) == missionArg(args)
	}
	o := s.currentOffer(shopper)
	amount, ok := spend.AmountFromScope(scope)
	return o != nil && ok && amount == o.TotalCents && spend.OrderFromScope(scope) == o.Hash()
}

// challengeFor answers requirement=auth-token for what tool needs.
func (s *Shop) challengeFor(w http.ResponseWriter, tool string, args json.RawMessage, shopper string, presented aauth.PresentedToken) {
	if tool != "mission_approve" {
		s.challengeCheckout(w, shopper, presented)
		return
	}
	m, ok := s.cfg.Selections.Get(missionArg(args))
	if !ok || m.Shopper != shopper {
		writeRPCError(w, nil, -32602, "unknown mission_id: propose one with mission_propose")
		return
	}
	s.challenge(w, selection.Scope(m), presented, fmt.Sprintf("selection mission %s: %s, %d products → requirement=auth-token", short(m.ID), m.Criteria.Summary(), len(m.Products)))
}

func missionArg(args json.RawMessage) string {
	var a struct {
		MissionID string `json:"mission_id"`
	}
	_ = json.Unmarshal(args, &a)
	return a.MissionID
}

// challenge issues a resource token for scope, addressed to ChipIn's
// access server, and answers requirement=auth-token.
func (s *Shop) challenge(w http.ResponseWriter, scope string, presented aauth.PresentedToken, msg string) {
	rt, err := aauth.IssueResourceToken(aauth.ResourceTokenParams{
		Resource: s.cfg.URL, Audience: s.cfg.AccessServer, Scope: scope,
	}, presented, s.key, s.kid)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.cfg.Log("ChipIn", msg)
	aauth.ChallengeAuthToken(w, rt)
}

// challengeCheckout answers requirement=auth-token with a resource token
// for exactly the order the shopper's cart holds (its amount and hash),
// addressed to ChipIn's access server (four-party).
func (s *Shop) challengeCheckout(w http.ResponseWriter, shopper string, presented aauth.PresentedToken) {
	o := s.currentOffer(shopper)
	if o == nil {
		writeRPCError(w, nil, -32602, "your cart is empty")
		return
	}
	if o.Selection == "" {
		writeRPCError(w, nil, -32602, "approve a selection mission first (mission_propose, mission_approve)")
		return
	}
	hash := o.Hash()
	s.mu.Lock()
	s.pending[hash] = o
	s.mu.Unlock()
	scope := spend.OrderScope(o.TotalCents, hash) + " selection:" + o.Selection
	s.challenge(w, scope, presented, fmt.Sprintf("offer %s: %d line(s), %s under selection %s → requirement=auth-token", short(hash), len(o.Items), spend.Dollars(o.TotalCents), short(o.Selection)))
}

func (s *Shop) isRevoked(iss, jti string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revoked[[2]string{iss, jti}]
}

// currentOffer is the order the shopper's cart holds now, or nil.
func (s *Shop) currentOffer(shopper string) *Offer {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.carts[shopper]
	if c == nil || len(c.Items) == 0 {
		return nil
	}
	o := &Offer{Merchant: s.cfg.URL, Shopper: shopper, TotalCents: total(c), Currency: spend.Currency, Nonce: c.Nonce}
	if m, ok := s.activeSelection(shopper); ok {
		o.Selection = m.ID
	}
	items := append([]Item(nil), c.Items...)
	sort.Slice(items, func(i, j int) bool { return items[i].Offer.ID < items[j].Offer.ID })
	for _, it := range items {
		o.Items = append(o.Items, OfferLine{OfferID: it.Offer.ID, Store: it.Offer.Store, Title: it.Offer.Title,
			VariantID: it.Offer.VariantID, Brand: it.Offer.Brand, Cans: it.Offer.Cans, UnitCents: it.Offer.PriceCents, Quantity: it.Quantity})
	}
	return o
}

// activeSelection is the shopper's approved selection mission. It takes
// no shop lock (the registry has its own), so it is safe under s.mu.
func (s *Shop) activeSelection(shopper string) (*selection.Mission, bool) {
	return s.cfg.Selections.Active(shopper)
}

func newNonce() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func total(c *cart) int64 {
	if c == nil {
		return 0
	}
	var t int64
	for _, it := range c.Items {
		t += it.Offer.PriceCents * int64(it.Quantity)
	}
	return t
}

func (s *Shop) callTool(ctx context.Context, c *caller, name string, raw json.RawMessage) (any, error) {
	var args struct {
		Query        string   `json:"query"`
		OfferID      string   `json:"offer_id"`
		Quantity     int      `json:"quantity"`
		PaymentToken string   `json:"payment_token"`
		Packs        []string `json:"packs"`
		Brands       []string `json:"brands"`
		MaxCostUSD   float64  `json:"max_cost_usd"`
		MissionID    string   `json:"mission_id"`
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, fmt.Errorf("bad arguments: %w", err)
		}
	}
	switch name {
	case "catalog_search":
		return s.search(ctx, args.Query)
	case "mission_propose":
		return s.propose(ctx, c.Shopper, selection.Criteria{Packs: args.Packs, Brands: args.Brands, MaxCostCents: int64(args.MaxCostUSD*100 + 0.5)})
	case "mission_approve":
		if err := s.cfg.Selections.Approve(args.MissionID, c.Auth.PS); err != nil {
			return nil, err
		}
		m, _ := s.cfg.Selections.Get(args.MissionID)
		s.cfg.Log("ChipIn", fmt.Sprintf("selection %s approved by the person at %s: %s", short(m.ID), c.Auth.PS, m.Criteria.Summary()))
		if s.cfg.Keycard != nil {
			pol, err := s.cfg.Keycard.Publish(ctx, keycard.Mission{ID: m.ID, Summary: m.Criteria.Summary(),
				Brands: m.Criteria.Brands, Packs: m.Criteria.Packs, MaxCostCents: m.Criteria.MaxCostCents})
			if err != nil {
				return nil, err
			}
			s.cfg.Selections.SetKeycardPolicy(m.ID, pol.ID, pol.Name)
			m, _ = s.cfg.Selections.Get(args.MissionID)
			s.cfg.Log("Keycard", fmt.Sprintf("published Cedar policy %s for the mission: %s", pol.Name, m.Criteria.Summary()))
		}
		return map[string]any{"mission": m, "summary": m.Criteria.Summary(), "enforced_by": orDefault(m.KeycardPolicyName, "ChipIn (local rules)")}, nil
	case "cart_add":
		return s.cartAdd(c.Shopper, args.OfferID, args.Quantity)
	case "cart_view", "checkout_quote":
		return s.cartView(c.Shopper), nil
	case "cart_remove":
		return s.cartRemove(c.Shopper, args.OfferID)
	case "checkout_authorize":
		amount, _ := spend.AmountFromScope(c.Auth.Scope)
		hash := spend.OrderFromScope(c.Auth.Scope)
		s.cfg.Log("ChipIn", fmt.Sprintf("order %s approved: %s, auth token from %s (person at %s)", short(hash), spend.Dollars(amount), c.Auth.Issuer, c.Auth.PS))
		return map[string]any{"authorized_cents": amount, "authorized": spend.Dollars(amount), "order_hash": hash,
			"order_url": s.cfg.URL + "/orders/" + hash, "authorized_by": c.Auth.Issuer, "mission_s256": c.Auth.MissionS256}, nil
	case "checkout_pay":
		return s.pay(ctx, c, args.PaymentToken)
	}
	return nil, fmt.Errorf("unknown tool %q", name)
}

func (s *Shop) search(ctx context.Context, query string) (any, error) {
	if strings.TrimSpace(query) == "" {
		query = "tennis balls"
	}
	res, err := s.cfg.Catalog.Search(ctx, query)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	for _, o := range res.Offers {
		s.offers[o.ID] = o
	}
	s.mu.Unlock()
	src := "live (UCP)"
	if res.Recorded {
		src = "recorded fixture"
	}
	s.cfg.Log("ChipIn", fmt.Sprintf("catalog_search %q: %d offers from %d stores, %s", query, len(res.Offers), len(s.cfg.Catalog.Stores), src))
	return map[string]any{"source": src, "offers": res.Offers, "store_errors": res.Errors}, nil
}

// propose builds a selection mission: searches every chosen brand across
// the UCP stores and keeps the products that match the player's choices.
func (s *Shop) propose(ctx context.Context, shopper string, c selection.Criteria) (any, error) {
	c, err := c.Normalize()
	if err != nil {
		return nil, err
	}
	var all []ucp.Offer
	src := "live (UCP)"
	// Each chosen brand, plus pack-size searches: stores' search ranking
	// differs, and a query a store fails on must not sink the mission.
	queries := []string{}
	for _, b := range c.Brands {
		queries = append(queries, b+" tennis balls")
	}
	queries = append(queries, "tennis balls 12 cans", "tennis ball case", "tennis balls 18 cans")
	for _, q := range queries {
		res, err := s.cfg.Catalog.Search(ctx, q)
		if err != nil {
			s.cfg.Log("ChipIn", fmt.Sprintf("search %q failed: %v", q, err))
			continue
		}
		if res.Recorded {
			src = "recorded fixture"
		}
		all = append(all, res.Offers...)
	}
	s.mu.Lock()
	for _, o := range all {
		s.offers[o.ID] = o
	}
	s.mu.Unlock()
	seen := map[string]bool{}
	uniq := all[:0]
	for _, o := range all {
		if !seen[o.ID] {
			seen[o.ID] = true
			uniq = append(uniq, o)
		}
	}
	all = uniq
	m := selection.New(shopper, c, all)
	if len(m.Products) == 0 {
		return nil, fmt.Errorf("no products match %s (%d offers searched, %s)", c.Summary(), len(all), src)
	}
	s.cfg.Selections.Put(m)
	s.cfg.Log("ChipIn", fmt.Sprintf("selection proposed: %s → %d of %d offers across the UCP stores (%s)", c.Summary(), len(m.Products), len(all), src))
	return map[string]any{"mission": m, "summary": c.Summary(), "approval_scope": selection.Scope(m),
		"mission_url": s.cfg.URL + "/missions/" + m.ID, "source": src}, nil
}

func (s *Shop) cartAdd(shopper, offerID string, qty int) (any, error) {
	if qty <= 0 {
		qty = 1
	}
	m, hasMission := s.activeSelection(shopper)
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.offers[offerID]
	if !ok {
		return nil, fmt.Errorf("unknown offer %q: search first", offerID)
	}
	if !o.Available {
		return nil, fmt.Errorf("%s is out of stock at %s", o.Title, o.Store)
	}
	if !hasMission {
		return nil, errors.New("approve a selection mission first (mission_propose, mission_approve)")
	}
	_ = m // the mission is enforced at checkout, by Keycard
	c := s.carts[shopper]
	if c == nil {
		c = &cart{}
		s.carts[shopper] = c
	}
	c.Nonce = newNonce()
	for i := range c.Items {
		if c.Items[i].Offer.ID == offerID {
			c.Items[i].Quantity += qty
			return cartJSON(c), nil
		}
	}
	c.Items = append(c.Items, Item{Offer: o, Quantity: qty})
	return cartJSON(c), nil
}

func (s *Shop) cartRemove(shopper, offerID string) (any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.carts[shopper]
	if c == nil {
		return cartJSON(&cart{}), nil
	}
	c.Nonce = newNonce()
	kept := c.Items[:0]
	for _, it := range c.Items {
		if it.Offer.ID != offerID {
			kept = append(kept, it)
		}
	}
	c.Items = kept
	return cartJSON(c), nil
}

func (s *Shop) cartView(shopper string) any {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.carts[shopper]
	if c == nil {
		c = &cart{}
	}
	return cartJSON(c)
}

func cartJSON(c *cart) map[string]any {
	items := append([]Item(nil), c.Items...)
	sort.Slice(items, func(i, j int) bool { return items[i].Offer.ID < items[j].Offer.ID })
	t := total(c)
	return map[string]any{
		"items": items, "total_cents": t, "total": spend.Dollars(t),
		"checkout_scope": spend.CheckoutScope(t),
	}
}

// pay charges the cart the auth token authorized (authenticate already
// checked the amount) and records the order.
func (s *Shop) pay(ctx context.Context, c *caller, spt string) (any, error) {
	offer := s.currentOffer(c.Shopper)
	if offer == nil {
		return nil, errors.New("your cart is empty")
	}
	hash := offer.Hash()
	s.mu.Lock()
	if s.paid[hash] {
		s.mu.Unlock()
		return nil, errors.New("this order is already paid")
	}
	s.paid[hash] = true // claim it before charging, so a retry cannot pay twice
	items := append([]Item(nil), s.carts[c.Shopper].Items...)
	amount := offer.TotalCents
	s.mu.Unlock()

	orderID := fmt.Sprintf("ord_%d", time.Now().UnixNano())
	o := Order{
		ID: orderID, Shopper: c.Shopper, Items: items, TotalCents: amount, OrderHash: hash,
		Mission: c.Auth.MissionS256, AuthorizedBy: c.Auth.Issuer,
		Fulfillment: "simulated: ChipIn is a demo merchant and places no order at " + storesOf(items),
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
	}
	if s.cfg.Stripe == nil {
		o.PaymentStatus = "skipped (no Stripe key configured)"
	} else {
		mission := c.Auth.MissionS256
		pi, err := s.cfg.Stripe.Pay(ctx, payments.Charge{
			AmountCents:    amount,
			Description:    fmt.Sprintf("ChipIn order %s (AAuth demo)", orderID),
			SPT:            spt,
			IdempotencyKey: hash,
			Metadata: map[string]string{
				"app": "chip-in", "order_id": orderID, "order_hash": hash, "authorized_by": c.Auth.Issuer, "person_server": c.Auth.PS,
				"auth_token_jti": c.Auth.ID, "mission_s256": mission,
			},
		})
		if err != nil {
			s.mu.Lock()
			delete(s.paid, hash) // nothing was charged: the order may be paid again
			s.mu.Unlock()
			return nil, fmt.Errorf("payment failed: %w", err)
		}
		o.PaymentIntent, o.PaymentStatus, o.DashboardURL = pi.ID, pi.Status, pi.DashboardURL()
		o.PaidWith = "test_card"
		if spt != "" {
			o.PaidWith = "shared_payment_token"
		}
	}
	s.mu.Lock()
	s.spent[offer.Selection] += amount
	s.orders = append(s.orders, o)
	delete(s.carts, c.Shopper)
	s.mu.Unlock()
	s.cfg.Log("ChipIn", fmt.Sprintf("order %s paid %s via %s: %s", orderID, spend.Dollars(amount), orDefault(o.PaidWith, "nothing"), o.PaymentStatus))
	return o, nil
}

func storesOf(items []Item) string {
	seen := map[string]bool{}
	var names []string
	for _, it := range items {
		if !seen[it.Offer.Store] {
			seen[it.Offer.Store] = true
			names = append(names, it.Offer.Store)
		}
	}
	return strings.Join(names, " and ")
}

func toolList() []map[string]any {
	obj := func(props map[string]any, required ...string) map[string]any {
		m := map[string]any{"type": "object", "properties": props}
		if len(required) > 0 {
			m["required"] = required
		}
		return m
	}
	str := func(d string) map[string]any { return map[string]any{"type": "string", "description": d} }
	return []map[string]any{
		{"name": "catalog_search", "description": "Search live tennis ball offers at Tennis Express and Holabird Sports (UCP). Needs: agent token.",
			"inputSchema": obj(map[string]any{"query": str("what to look for, e.g. 'Penn Championship extra duty'")})},
		{"name": "mission_propose", "description": "Propose a product-selection mission from the player's choices; returns the matching products across the UCP stores. Needs: person token.",
			"inputSchema": obj(map[string]any{
				"packs":        map[string]any{"type": "array", "items": map[string]any{"type": "string", "enum": selection.PackOrder}, "description": "pack sizes, in cans: 12, 18, 24"},
				"brands":       map[string]any{"type": "array", "items": map[string]any{"type": "string", "enum": selection.Brands}},
				"max_cost_usd": map[string]any{"type": "number", "description": "most to spend under the mission"},
			}, "packs", "brands", "max_cost_usd")},
		{"name": "mission_approve", "description": "Have the player approve the selection at their person server; afterwards only its products can be bought. Needs: auth token for the mission.",
			"inputSchema": obj(map[string]any{"mission_id": str("id from mission_propose")}, "mission_id")},
		{"name": "cart_add", "description": "Add an offer to your cart. Needs: person token.",
			"inputSchema": obj(map[string]any{"offer_id": str("an id from catalog_search"), "quantity": map[string]any{"type": "integer", "minimum": 1}}, "offer_id")},
		{"name": "cart_view", "description": "Show your cart. Needs: person token.", "inputSchema": obj(map[string]any{})},
		{"name": "cart_remove", "description": "Remove an offer from your cart. Needs: person token.",
			"inputSchema": obj(map[string]any{"offer_id": str("the offer to remove")}, "offer_id")},
		{"name": "checkout_quote", "description": "The cart total and the AAuth scope checkout_pay will require. Needs: person token.", "inputSchema": obj(map[string]any{})},
		{"name": "checkout_authorize", "description": "Have your person approve this exact order before minting a payment credential. Needs: an auth token whose scope names this order's amount and hash.", "inputSchema": obj(map[string]any{})},
		{"name": "checkout_pay", "description": "Pay for the approved order. Needs: an auth token whose scope names this order's amount and hash. Pays with a Stripe shared payment token when given, else Stripe's test card.",
			"inputSchema": obj(map[string]any{"payment_token": str("Stripe shared payment token (spt_...), capped at the cart total")})},
	}
}

func toolResult(out any, err error) map[string]any {
	if err != nil {
		return map[string]any{"isError": true, "content": []map[string]any{{"type": "text", "text": err.Error()}}}
	}
	b, _ := json.Marshal(out)
	return map[string]any{
		"content":           []map[string]any{{"type": "text", "text": string(b)}},
		"structuredContent": out,
	}
}

func writeRPCError(w http.ResponseWriter, id json.RawMessage, code int, msg string) {
	writeJSON(w, http.StatusOK, map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": code, "message": msg}})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func short(h string) string {
	if len(h) > 10 {
		return h[:10] + "…"
	}
	return h
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
