// Package selection is the product-selection mission: the player chooses
// pack sizes, brands, and a maximum cost; ChipIn finds the matching
// products across the UCP stores; the player approves that list at their
// person server; afterwards only those products, under that cost, can be
// bought for them.
package selection

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gkedev/adelaide/internal/spend"
	"github.com/gkedev/adelaide/internal/ucp"
)

// Pack sizes a player can choose, in cans: the multi-can packs the UCP
// stores actually sell. No single cans (not worth buying and shipping), and
// no 3-, 4- or 8-packs (neither store lists any).
var Packs = map[string]int{"12": 12, "18": 18, "24": 24}

// PackOrder lists the pack choices in display order.
var PackOrder = []string{"12", "18", "24"}

// Brands a player can choose.
var Brands = []string{"Dunlop", "Penn", "Tecnifibre", "Wilson"}

// Criteria are the player's choices.
type Criteria struct {
	Packs        []string `json:"packs"`  // "12", "18", "24" (cans)
	Brands       []string `json:"brands"` // Brands
	MaxCostCents int64    `json:"max_cost_cents"`
}

// Normalize validates the criteria and puts them in canonical form.
func (c Criteria) Normalize() (Criteria, error) {
	var out Criteria
	for _, p := range c.Packs {
		p = strings.ToLower(strings.TrimSpace(p))
		for _, suf := range []string{"-pack", " pack", "pack", "-can", " cans", "cans"} {
			p = strings.TrimSuffix(p, suf)
		}
		if _, ok := Packs[p]; !ok {
			return out, fmt.Errorf("unknown pack %q: choose from 12, 18, 24-pack", p)
		}
		if !slices.Contains(out.Packs, p) {
			out.Packs = append(out.Packs, p)
		}
	}
	for _, b := range c.Brands {
		i := slices.IndexFunc(Brands, func(x string) bool { return strings.EqualFold(x, strings.TrimSpace(b)) })
		if i < 0 {
			return out, fmt.Errorf("unknown brand %q: choose from %s", b, strings.Join(Brands, ", "))
		}
		if !slices.Contains(out.Brands, Brands[i]) {
			out.Brands = append(out.Brands, Brands[i])
		}
	}
	if len(out.Packs) == 0 || len(out.Brands) == 0 || c.MaxCostCents <= 0 {
		return out, errors.New("choose at least one pack size, one brand, and a max cost")
	}
	slices.SortFunc(out.Packs, func(a, b string) int { return Packs[a] - Packs[b] })
	slices.Sort(out.Brands)
	out.MaxCostCents = c.MaxCostCents
	return out, nil
}

// excluded listings are not pressurized adult balls.
var excluded = []string{"foam", "starter", "stage", "junior", "kids", "pressureless", "low compression", "qst", "pickleball", "padel", "hopper", "basket", "green dot", "orange", "red ", "coach", "practice", "teaching", "training", "logo"}

// Matches reports whether an offer fits the criteria.
func (c Criteria) Matches(o ucp.Offer) bool {
	t := strings.ToLower(o.Title) + " "
	for _, w := range excluded {
		if strings.Contains(t, w) {
			return false
		}
	}
	if !o.Available || o.Currency != spend.Currency || o.PriceCents <= 0 || o.PriceCents > c.MaxCostCents {
		return false
	}
	if !slices.Contains(c.Brands, o.Brand) {
		return false
	}
	for _, p := range c.Packs {
		if Packs[p] == o.Cans {
			return true
		}
	}
	return false
}

// Summary describes the criteria in words.
func (c Criteria) Summary() string {
	packs := make([]string, len(c.Packs))
	for i, p := range c.Packs {
		packs[i] = p + "-pack"
	}
	return fmt.Sprintf("%s · %s · up to %s", strings.Join(c.Brands, ", "), strings.Join(packs, ", "), spend.Dollars(c.MaxCostCents))
}

// Product is one authorized product, as offered when the mission was made.
type Product struct {
	OfferID    string `json:"offer_id"`
	Store      string `json:"store"`
	Title      string `json:"title"`
	Brand      string `json:"brand"`
	Cans       int    `json:"cans"`
	PriceCents int64  `json:"price_cents"`
	URL        string `json:"url,omitempty"`
}

// Mission is a selection mission.
type Mission struct {
	ID       string    `json:"id"` // hash of the proposal
	Shopper  string    `json:"shopper"`
	Criteria Criteria  `json:"criteria"`
	Products []Product `json:"products"`
	Status   string    `json:"status"` // "proposed", "approved"
	// KeycardPolicy names the Keycard policy enforcing the mission, once published.
	KeycardPolicyID   string `json:"keycard_policy_id,omitempty"`
	KeycardPolicyName string `json:"keycard_policy_name,omitempty"`
	ApprovedBy        string `json:"approved_by,omitempty"`
	CreatedAt         string `json:"created_at"`
	Nonce             string `json:"nonce"`
}

// Allows reports whether the mission authorizes this offer at this price.
func (m *Mission) Allows(offerID string, unitCents int64) bool {
	for _, p := range m.Products {
		if p.OfferID == offerID && unitCents <= p.PriceCents {
			return true
		}
	}
	return false
}

// New builds a proposed mission from the offers that match c.
func New(shopper string, c Criteria, offers []ucp.Offer) *Mission {
	m := &Mission{Shopper: shopper, Criteria: c, Status: "proposed", CreatedAt: time.Now().UTC().Format(time.RFC3339)}
	seen := map[string]bool{}
	for _, o := range offers {
		if c.Matches(o) && !seen[o.ID] {
			seen[o.ID] = true
			m.Products = append(m.Products, Product{OfferID: o.ID, Store: o.Store, Title: o.Title, Brand: o.Brand, Cans: o.Cans, PriceCents: o.PriceCents, URL: o.URL})
		}
	}
	slices.SortFunc(m.Products, func(a, b Product) int { return int(a.PriceCents - b.PriceCents) })
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	m.Nonce = hex.EncodeToString(b)
	body, _ := json.Marshal(struct {
		Shopper  string    `json:"shopper"`
		Criteria Criteria  `json:"criteria"`
		Products []Product `json:"products"`
		Nonce    string    `json:"nonce"`
	}{m.Shopper, m.Criteria, m.Products, m.Nonce})
	sum := sha256.Sum256(body)
	m.ID = base64.RawURLEncoding.EncodeToString(sum[:])
	return m
}

// Scope is the AAuth scope approving mission m: "mission:approve
// selection:<id> max:usd:<cents>".
func Scope(m *Mission) string {
	return fmt.Sprintf("mission:approve selection:%s max:%s:%d", m.ID, spend.Currency, m.Criteria.MaxCostCents)
}

// FromScope returns the selection id an AAuth scope names, or "".
func FromScope(scope string) string {
	for _, s := range strings.Fields(scope) {
		if id, ok := strings.CutPrefix(s, "selection:"); ok {
			return id
		}
	}
	return ""
}

// IsApproval reports whether scope approves a mission.
func IsApproval(scope string) bool { return slices.Contains(strings.Fields(scope), "mission:approve") }

// Registry holds missions in memory.
type Registry struct {
	mu       sync.Mutex
	byID     map[string]*Mission
	approved map[string]string // shopper → approved mission id
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{byID: map[string]*Mission{}, approved: map[string]string{}}
}

// Put stores a proposed mission.
func (r *Registry) Put(m *Mission) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byID[m.ID] = m
}

// Get returns a copy of mission id.
func (r *Registry) Get(id string) (*Mission, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	m, ok := r.byID[id]
	if !ok {
		return nil, false
	}
	c := *m
	return &c, true
}

// Approve marks mission id approved for its shopper, replacing any earlier one.
func (r *Registry) Approve(id, approvedBy string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	m, ok := r.byID[id]
	if !ok {
		return errors.New("unknown mission")
	}
	m.Status, m.ApprovedBy = "approved", approvedBy
	r.approved[m.Shopper] = id
	return nil
}

// SetKeycardPolicy records the Keycard policy enforcing mission id.
func (r *Registry) SetKeycardPolicy(id, policyID, name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if m, ok := r.byID[id]; ok {
		m.KeycardPolicyID, m.KeycardPolicyName = policyID, name
	}
}

// PackOf is the pack choice a listing of cans falls under ("12", "18",
// "24"), or "".
func PackOf(cans int) string {
	for p, n := range Packs {
		if n == cans {
			return p
		}
	}
	return ""
}

// Active returns the shopper's approved mission.
func (r *Registry) Active(shopper string) (*Mission, bool) {
	r.mu.Lock()
	id, ok := r.approved[shopper]
	r.mu.Unlock()
	if !ok {
		return nil, false
	}
	return r.Get(id)
}
