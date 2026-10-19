// Package trust hosts the AAuth roles ChipIn runs itself, on ChipIn's own
// origin, built on aauth-go v0.2 (draft-hardt-oauth-aauth-protocol-11):
//
//   - the agent provider that issues the shopping agent its agent token,
//     naming the person's server (Hellō, https://person.hello.coop) as ps;
//   - the ChipIn access server (four-party, §9.1): the person server
//     federates each purchase here, and ChipIn's policy decides it.
//
// The person server is not here: players sign in and approve at Hellō.
package trust

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	aauth "github.com/aauth-dev/aauth-go"
	"github.com/aauth-dev/aauth-go/accessserver"
	"github.com/aauth-dev/aauth-go/agentprovider"

	"github.com/gkedev/adelaide/internal/spend"
)

// EnrollHeader carries the enrollment secret an agent install presents to
// the agent provider (the demo's stand-in for signing in on a device), and
// AgentNameHeader optionally names the install (one agent per player).
const (
	EnrollHeader    = "X-Chipin-Enrollment"
	AgentNameHeader = "X-Chipin-Agent"
)

var agentName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,40}$`)

// Config configures the roles.
type Config struct {
	// Issuer is ChipIn's origin, shared by the agent provider, the access
	// server, and the shop (each with its own key and metadata document).
	Issuer string
	// ShopURL is the resource the access server governs (normally Issuer).
	ShopURL string
	// PS is the person server the agents' tokens name: Hellō in the live demo.
	PS string
	// SupervisedPS, when set, is the person server named instead for agent
	// installs whose name starts with "sup-" (the Supervisor demo).
	SupervisedPS string
	// AgentDomain is the domain of the agent identifiers issued.
	AgentDomain string
	// APKey and ASKey are the signing keys (generated when nil).
	APKey, ASKey crypto.Signer
	// DailyBudgetCents is the most one person may spend at ChipIn per day.
	DailyBudgetCents int64
	// MaxOrderCents is the per-order cap.
	MaxOrderCents int64
	// EnrollmentSecret authorizes agent installs at the agent provider.
	EnrollmentSecret string
	// Authorize, when set, is the shop's check that what the person
	// approved matches what the shop offered them (and their mission).
	Authorize func(scope, ps, sub string) error
	// HTTPClient is used for discovery (nil: aauth.DiscoveryClient).
	HTTPClient *http.Client
	// Insecure accepts http://localhost identifiers (tests only).
	Insecure bool
	// Log reports each decision for the demo trace.
	Log func(role, msg string)
}

// Roles are the running agent provider and access server.
type Roles struct {
	cfg Config
	AP  *agentprovider.Server
	AS  *accessserver.Server

	mu    sync.Mutex
	spent map[string]spending // "ps|sub" → today's authorized total
	seen  map[string]bool     // order hashes already authorized
}

type spending struct {
	day   string
	cents int64
}

// New builds the roles.
func New(cfg Config) (*Roles, error) {
	if cfg.Issuer == "" || cfg.PS == "" {
		return nil, errors.New("trust: Issuer and PS are required")
	}
	if cfg.ShopURL == "" {
		cfg.ShopURL = cfg.Issuer
	}
	if cfg.AgentDomain == "" {
		cfg.AgentDomain = hostOf(cfg.Issuer)
	}
	if cfg.Log == nil {
		cfg.Log = func(string, string) {}
	}
	var err error
	if cfg.APKey == nil {
		if cfg.APKey, err = aauth.GenerateKey(aauth.AlgEd25519); err != nil {
			return nil, err
		}
	}
	if cfg.ASKey == nil {
		if cfg.ASKey, err = aauth.GenerateKey(aauth.AlgES256); err != nil {
			return nil, err
		}
	}
	r := &Roles{cfg: cfg, spent: map[string]spending{}, seen: map[string]bool{}}
	resolver := aauth.NewJWKSResolver(cfg.HTTPClient)

	r.AP, err = agentprovider.New(agentprovider.Config{
		HTTPClient: cfg.HTTPClient,
		Issuer:     cfg.Issuer,
		Domain:     cfg.AgentDomain,
		Key:        cfg.APKey,
		Registrar:  enrollment{r},
		OnIssue: func(_ context.Context, it agentprovider.IssuedToken) {
			cfg.Log("ChipIn AP", "issued agent token to "+it.Claims.Subject+" (ps "+it.Claims.PS+")")
		},
	})
	if err != nil {
		return nil, fmt.Errorf("trust: agent provider: %w", err)
	}
	r.AS, err = accessserver.New(accessserver.Config{
		HTTPClient:                  cfg.HTTPClient,
		Issuer:                      cfg.Issuer,
		Key:                         cfg.ASKey,
		Store:                       accessserver.NewMemoryStore(),
		AgentResolver:               resolver,
		TokenResolver:               resolver,
		ServerResolver:              resolver,
		Resources:                   func(res string) bool { return res == cfg.ShopURL },
		Authorizer:                  accessserver.AuthorizerFunc(r.policy),
		InsecureSkipIdentifierCheck: cfg.Insecure,
	})
	if err != nil {
		return nil, fmt.Errorf("trust: access server: %w", err)
	}
	return r, nil
}

// Register adds both roles' routes (/.well-known/aauth-agent.json, /ap/*,
// /.well-known/aauth-access.json, /as/*) to mux.
func (r *Roles) Register(mux *http.ServeMux) {
	r.AP.Register(mux)
	r.AS.Register(mux)
}

// policy is ChipIn's purchase policy. The person server has already had
// the person (or their supervisor) approve the order; ChipIn checks that
// the request names one specific order, under the per-order cap and the
// person's daily budget.
func (r *Roles) policy(_ context.Context, req *accessserver.AuthorizationRequest) (accessserver.Decision, error) {
	rc := req.Resource
	amount, ok := spend.AmountFromScope(rc.Scope)
	if !ok {
		if r.cfg.Authorize != nil {
			if err := r.cfg.Authorize(rc.Scope, rc.PS, rc.Subject); err != nil {
				r.cfg.Log("ChipIn AS", "DENY: "+err.Error())
				return accessserver.Deny(err.Error()), nil
			}
		}
		return accessserver.Allow(""), nil // not a payment
	}
	order := spend.OrderFromScope(rc.Scope)
	if order == "" {
		r.cfg.Log("ChipIn AS", "DENY: payment scope names no order")
		return accessserver.Deny("a payment must name one specific order"), nil
	}
	if r.cfg.MaxOrderCents > 0 && amount > r.cfg.MaxOrderCents {
		r.cfg.Log("ChipIn AS", fmt.Sprintf("DENY %s: above the per-order cap %s", spend.Dollars(amount), spend.Dollars(r.cfg.MaxOrderCents)))
		return accessserver.Deny(fmt.Sprintf("orders above %s need a human at ChipIn", spend.Dollars(r.cfg.MaxOrderCents))), nil
	}
	who := rc.PS + "|" + rc.Subject
	today := time.Now().UTC().Format("2006-01-02")
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.seen[order] {
		r.cfg.Log("ChipIn AS", "DENY: order "+short(order)+" was already authorized")
		return accessserver.Deny("this order was already authorized"), nil
	}
	sp := r.spent[who]
	if sp.day != today {
		sp = spending{day: today}
	}
	if b := r.cfg.DailyBudgetCents; b > 0 && sp.cents+amount > b {
		r.cfg.Log("ChipIn AS", fmt.Sprintf("DENY %s for order %s: over the daily budget (%s of %s used)", spend.Dollars(amount), short(order), spend.Dollars(sp.cents), spend.Dollars(b)))
		return accessserver.Deny(fmt.Sprintf("%s exceeds your ChipIn daily budget: %s of %s left", spend.Dollars(amount), spend.Dollars(b-sp.cents), spend.Dollars(b))), nil
	}
	if r.cfg.Authorize != nil {
		if err := r.cfg.Authorize(rc.Scope, rc.PS, rc.Subject); err != nil {
			r.cfg.Log("ChipIn AS", fmt.Sprintf("DENY %s for order %s: %v", spend.Dollars(amount), short(order), err))
			return accessserver.Deny(err.Error()), nil
		}
	}
	sp.cents += amount
	r.spent[who] = sp
	r.seen[order] = true
	r.cfg.Log("ChipIn AS", fmt.Sprintf("ALLOW %s for order %s, approved at %s", spend.Dollars(amount), short(order), rc.PS))
	return accessserver.Allow(""), nil
}

type enrollment struct{ r *Roles }

func (e enrollment) AuthorizeIssue(_ context.Context, req *http.Request, _ *agentprovider.IssueRequest) (*agentprovider.Registration, error) {
	if e.r.cfg.EnrollmentSecret == "" || req.Header.Get(EnrollHeader) != e.r.cfg.EnrollmentSecret {
		return nil, errors.New("unknown agent install")
	}
	name := "chipin-shopper"
	if n := req.Header.Get(AgentNameHeader); n != "" {
		if !agentName.MatchString(n) {
			return nil, errors.New("bad agent name")
		}
		name = n
	}
	ps := e.r.cfg.PS
	if e.r.cfg.SupervisedPS != "" && strings.HasPrefix(name, "sup-") {
		ps = e.r.cfg.SupervisedPS
	}
	return &agentprovider.Registration{Name: name, PS: ps}, nil
}

func (enrollment) AuthorizeRefresh(context.Context, *agentprovider.RefreshRequest) (*agentprovider.Registration, error) {
	return nil, errors.New("refresh is not used in the demo")
}

func (enrollment) AuthorizeSubagent(context.Context, *agentprovider.SubagentRequest) (*agentprovider.SubagentGrant, error) {
	return nil, errors.New("sub-agents are not used in the demo")
}

func hostOf(u string) string {
	for _, p := range []string{"https://", "http://"} {
		if len(u) > len(p) && u[:len(p)] == p {
			u = u[len(p):]
		}
	}
	for i, c := range u {
		if c == ':' || c == '/' {
			return u[:i]
		}
	}
	return u
}

func short(h string) string {
	if len(h) > 10 {
		return h[:10] + "…"
	}
	return h
}
