// Package ucp searches real retailers' catalogs over the Universal Commerce
// Protocol (https://ucp.dev): it discovers each store's shopping service at
// /.well-known/ucp and calls its MCP search_catalog tool, identifying the
// caller with a hosted UCP agent profile.
//
// Only catalog reads are made. The demo never creates carts or completes
// checkouts at real stores.
package ucp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Store is a retailer with a UCP shopping service.
type Store struct {
	Name   string `json:"name"`   // "Tennis Express"
	Domain string `json:"domain"` // "tennisexpress.com"
	Code   string `json:"code"`   // short prefix for offer ids: "te"
	// Endpoint is the MCP endpoint; empty means discover it from Domain.
	Endpoint string `json:"endpoint,omitempty"`
}

// DefaultStores are the live tennis retailers the demo searches.
var DefaultStores = []Store{
	{Name: "Tennis Express", Domain: "tennisexpress.com", Code: "te"},
	{Name: "Holabird Sports", Domain: "www.holabirdsports.com", Code: "hb"},
}

// Offer is one purchasable variant at one store, normalized for the demo.
type Offer struct {
	ID         string `json:"id"` // stable: store code + hash of the variant id
	Store      string `json:"store"`
	ProductID  string `json:"product_id"`
	VariantID  string `json:"variant_id"`
	Title      string `json:"title"`
	URL        string `json:"url,omitempty"`
	PriceCents int64  `json:"price_cents"`
	Currency   string `json:"currency"`
	Available  bool   `json:"available"`
	// Balls is the number of balls the variant contains, guessed from its
	// title ("24 Cans" is 72); zero when unknown.
	Balls int `json:"balls,omitempty"`
	// Cans is the number of 3-ball cans (1 for a can, 24 for a case); zero
	// when the listing is not sold in cans.
	Cans int `json:"cans,omitempty"`
	// Brand is the ball brand, from the title, the store's tags, and known
	// product lines; "" when unknown.
	Brand string   `json:"brand,omitempty"`
	Tags  []string `json:"tags,omitempty"`
}

// PerBallCents is the price per ball, or zero when Balls is unknown.
func (o Offer) PerBallCents() int64 {
	if o.Balls <= 0 {
		return 0
	}
	return (o.PriceCents + int64(o.Balls)/2) / int64(o.Balls)
}

// Client searches stores.
type Client struct {
	Stores []Store
	// Profile is this platform's UCP agent profile URL, sent with every
	// call (UCP: platforms MUST advertise their profile).
	Profile    string
	HTTPClient *http.Client
	// Fixture, when set, answers searches from recorded offers instead of
	// the network (offline rehearsal); results are labeled recorded.
	Fixture []Offer

	mu        sync.Mutex
	endpoints map[string]string
}

// Result is a search across stores.
type Result struct {
	Offers   []Offer           `json:"offers"`
	Errors   map[string]string `json:"errors,omitempty"` // store name → error
	Recorded bool              `json:"recorded,omitempty"`
}

// Search queries every store concurrently. A store that fails is reported
// in Errors; the others still answer.
func (c *Client) Search(ctx context.Context, query string) (*Result, error) {
	if c.Fixture != nil {
		return &Result{Offers: filterFixture(c.Fixture, query), Recorded: true}, nil
	}
	if c.Profile == "" {
		return nil, errors.New("ucp: an agent profile URL is required")
	}
	type answer struct {
		store  Store
		offers []Offer
		err    error
	}
	ch := make(chan answer, len(c.Stores))
	for _, s := range c.Stores {
		go func(s Store) {
			offers, err := c.searchStore(ctx, s, query)
			ch <- answer{s, offers, err}
		}(s)
	}
	res := &Result{}
	for range c.Stores {
		a := <-ch
		if a.err != nil {
			if res.Errors == nil {
				res.Errors = map[string]string{}
			}
			res.Errors[a.store.Name] = a.err.Error()
			continue
		}
		res.Offers = append(res.Offers, a.offers...)
	}
	sort.SliceStable(res.Offers, func(i, j int) bool { return res.Offers[i].ID < res.Offers[j].ID })
	if len(res.Offers) == 0 && len(res.Errors) == len(c.Stores) {
		return res, fmt.Errorf("ucp: every store failed: %v", res.Errors)
	}
	return res, nil
}

func (c *Client) hc() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: 20 * time.Second}
}

func (c *Client) endpoint(ctx context.Context, s Store) (string, error) {
	if s.Endpoint != "" {
		return s.Endpoint, nil
	}
	c.mu.Lock()
	ep, ok := c.endpoints[s.Domain]
	c.mu.Unlock()
	if ok {
		return ep, nil
	}
	ep, err := c.discover(ctx, s.Domain)
	if err != nil {
		return "", err
	}
	c.mu.Lock()
	if c.endpoints == nil {
		c.endpoints = map[string]string{}
	}
	c.endpoints[s.Domain] = ep
	c.mu.Unlock()
	return ep, nil
}

// discover reads the store's business profile and returns the endpoint of
// its MCP shopping service, preferring the profile's current version.
func (c *Client) discover(ctx context.Context, domain string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+domain+"/.well-known/ucp", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	res, err := c.hc().Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ucp: %s has no UCP profile (HTTP %d)", domain, res.StatusCode)
	}
	var prof struct {
		UCP struct {
			Version  string `json:"version"`
			Services map[string][]struct {
				Version   string `json:"version"`
				Transport string `json:"transport"`
				Endpoint  string `json:"endpoint"`
			} `json:"services"`
		} `json:"ucp"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&prof); err != nil {
		return "", fmt.Errorf("ucp: %s profile: %w", domain, err)
	}
	var fallback string
	for _, svc := range prof.UCP.Services["dev.ucp.shopping"] {
		if svc.Transport != "mcp" || !strings.HasPrefix(svc.Endpoint, "https://") {
			continue
		}
		if svc.Version == prof.UCP.Version {
			return svc.Endpoint, nil
		}
		if fallback == "" {
			fallback = svc.Endpoint
		}
	}
	if fallback == "" {
		return "", fmt.Errorf("ucp: %s offers no MCP shopping service", domain)
	}
	return fallback, nil
}

func (c *Client) searchStore(ctx context.Context, s Store, query string) ([]Offer, error) {
	ep, err := c.endpoint(ctx, s)
	if err != nil {
		return nil, err
	}
	call := map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{
			"name": "search_catalog",
			"arguments": map[string]any{
				"meta": map[string]any{"ucp-agent": map[string]any{"profile": c.Profile}},
				"catalog": map[string]any{
					"query":   query,
					"context": map[string]any{"address_country": "US", "currency": "USD"},
				},
			},
		},
	}
	b, _ := json.Marshal(call)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	res, err := c.hc().Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	var rpc struct {
		Result *struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
			Structured json.RawMessage `json:"structuredContent"`
			IsError    bool            `json:"isError"`
		} `json:"result"`
		Error *struct {
			Code    int             `json:"code"`
			Message string          `json:"message"`
			Data    json.RawMessage `json:"data"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &rpc); err != nil {
		return nil, fmt.Errorf("ucp: %s: HTTP %d, not JSON-RPC", s.Name, res.StatusCode)
	}
	if rpc.Error != nil {
		return nil, fmt.Errorf("ucp: %s: %s %s", s.Name, rpc.Error.Message, string(rpc.Error.Data))
	}
	if rpc.Result == nil {
		return nil, fmt.Errorf("ucp: %s: empty result", s.Name)
	}
	payload := []byte(rpc.Result.Structured)
	if len(payload) == 0 || string(payload) == "null" {
		for _, ct := range rpc.Result.Content {
			if ct.Type == "text" {
				payload = []byte(ct.Text)
				break
			}
		}
	}
	if rpc.Result.IsError {
		return nil, fmt.Errorf("ucp: %s: %s", s.Name, truncate(string(payload), 200))
	}
	var cat struct {
		Products []product `json:"products"`
	}
	if err := json.Unmarshal(payload, &cat); err != nil {
		return nil, fmt.Errorf("ucp: %s: products: %w", s.Name, err)
	}
	var offers []Offer
	for _, p := range cat.Products {
		offers = append(offers, p.offers(s)...)
	}
	return offers, nil
}

type money struct {
	Amount   int64  `json:"amount"` // minor units
	Currency string `json:"currency"`
}

type product struct {
	ID         string   `json:"id"`
	Title      string   `json:"title"`
	URL        string   `json:"url"`
	Tags       []string `json:"tags"`
	PriceRange struct {
		Min money `json:"min"`
	} `json:"price_range"`
	Variants []struct {
		ID           string          `json:"id"`
		Title        string          `json:"title"`
		URL          string          `json:"url"`
		Price        money           `json:"price"`
		Availability json.RawMessage `json:"availability"`
	} `json:"variants"`
}

// offers returns the product's variants as offers; a product listed
// without variants becomes one offer at its minimum price.
func (p product) offers(s Store) []Offer {
	if len(p.Variants) == 0 {
		return []Offer{newOffer(s, p.ID, p.ID, p.Title, p.URL, p.PriceRange.Min, true, p.Tags)}
	}
	var out []Offer
	for _, v := range p.Variants {
		title := p.Title
		if t := strings.TrimSpace(v.Title); t != "" && !strings.EqualFold(t, "Default Title") && !strings.EqualFold(t, p.Title) {
			title += " — " + t
		}
		u := v.URL
		if u == "" {
			u = p.URL
		}
		out = append(out, newOffer(s, p.ID, v.ID, title, u, v.Price, available(v.Availability), p.Tags))
	}
	return out
}

func newOffer(s Store, productID, variantID, title, u string, price money, avail bool, tags []string) Offer {
	sum := sha256.Sum256([]byte(s.Domain + "|" + variantID))
	return Offer{
		ID:         s.Code + "-" + hex.EncodeToString(sum[:])[:8],
		Store:      s.Name,
		ProductID:  productID,
		VariantID:  variantID,
		Title:      title,
		URL:        u,
		PriceCents: price.Amount,
		Currency:   strings.ToLower(price.Currency),
		Available:  avail,
		Balls:      BallsInTitle(title),
		Cans:       CansInTitle(title),
		Brand:      BrandOf(title, tags),
		Tags:       tags,
	}
}

// Brands the demo knows, and product lines whose titles omit the brand.
var (
	brands     = []string{"Dunlop", "Penn", "Tecnifibre", "Wilson", "Babolat", "Head", "Yonex", "Diadem", "Gamma", "Tourna"}
	brandLines = map[string]string{"us open": "Wilson", "triniti": "Wilson", "championship": "Penn", "marathon": "Penn",
		"tour extra": "Penn", "tour regular": "Penn", "grand prix": "Dunlop", "atp": "Dunlop", "x-one": "Tecnifibre", "court": "Tecnifibre"}
)

// BrandOf names the brand of a listing: a brand in the title wins, then a
// brand tag, then a known product line ("US Open" is Wilson).
func BrandOf(title string, tags []string) string {
	t := strings.ToLower(title)
	for _, b := range brands {
		if strings.Contains(t, strings.ToLower(b)) {
			return b
		}
	}
	for _, tag := range tags {
		for _, b := range brands {
			if strings.EqualFold(strings.TrimSpace(tag), b) {
				return b
			}
		}
	}
	for line, b := range brandLines {
		if strings.Contains(t, line) {
			return b
		}
	}
	return ""
}

var reNCans = regexp.MustCompile(`(?i)\b(\d+)[\s-]*cans?\b`)

// CansInTitle is the number of cans a listing holds: "24 Cans" 24, "4-Can
// Pack" 4, "Case" 24, "Can" 1; zero when it is not sold in cans.
func CansInTitle(title string) int {
	if m := reNCans.FindStringSubmatch(title); m != nil {
		n, _ := strconv.Atoi(m[1])
		return n
	}
	switch {
	case reCase.MatchString(title):
		return 24
	case reCan.MatchString(title):
		return 1
	}
	return 0
}

// available reads UCP availability, which stores send as an object
// ({"available": true}), a bool, or a status string; unknown means yes.
func available(raw json.RawMessage) bool {
	if len(raw) == 0 || string(raw) == "null" {
		return true
	}
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		return b
	}
	var obj struct {
		Available *bool  `json:"available"`
		Status    string `json:"status"`
	}
	if json.Unmarshal(raw, &obj) == nil {
		if obj.Available != nil {
			return *obj.Available
		}
		if obj.Status != "" {
			return !strings.Contains(strings.ToLower(obj.Status), "out")
		}
	}
	var str string
	if json.Unmarshal(raw, &str) == nil {
		return !strings.Contains(strings.ToLower(str), "out")
	}
	return true
}

var (
	reBalls = regexp.MustCompile(`(?i)\b(\d+)\s*balls?\b`)
	reBagOf = regexp.MustCompile(`(?i)\bbag of (\d+)\b`)
	reCans  = regexp.MustCompile(`(?i)\b(\d+)\s*cans?\b`)
	rePack  = regexp.MustCompile(`(?i)\b(\d+)\s*pack\b`)
	reCase  = regexp.MustCompile(`(?i)\bcase\b`)
	reCan   = regexp.MustCompile(`(?i)\bcan\b`)
)

// BallsInTitle guesses how many balls a listing holds from its title: "72
// Balls" is 72, "Bag of 12" 12, "24 Cans" 72, "Case" 72 (24 cans), "Can" 3,
// "6 Pack" 6. Zero when the title gives no clue.
func BallsInTitle(title string) int {
	atoi := func(s string) int { n, _ := strconv.Atoi(s); return n }
	switch {
	case reBalls.MatchString(title):
		return atoi(reBalls.FindStringSubmatch(title)[1])
	case reBagOf.MatchString(title):
		return atoi(reBagOf.FindStringSubmatch(title)[1])
	case reCans.MatchString(title):
		return 3 * atoi(reCans.FindStringSubmatch(title)[1])
	case reCase.MatchString(title):
		return 72
	case reCan.MatchString(title):
		return 3
	case rePack.MatchString(title):
		return atoi(rePack.FindStringSubmatch(title)[1])
	}
	return 0
}

// LoadFixture reads recorded offers written by SaveFixture.
func LoadFixture(path string) ([]Offer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f struct {
		Offers []Offer `json:"offers"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	return f.Offers, nil
}

// SaveFixture records offers for offline rehearsal.
func SaveFixture(path string, offers []Offer, note string) error {
	b, err := json.MarshalIndent(map[string]any{"note": note, "recorded_at": time.Now().UTC().Format(time.RFC3339), "offers": offers}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

func filterFixture(offers []Offer, query string) []Offer {
	words := strings.Fields(strings.ToLower(query))
	var out []Offer
	for _, o := range offers {
		t := strings.ToLower(o.Title)
		match := len(words) == 0
		for _, w := range words {
			if strings.Contains(t, strings.TrimSuffix(w, "s")) {
				match = true
				break
			}
		}
		if match {
			out = append(out, o)
		}
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
