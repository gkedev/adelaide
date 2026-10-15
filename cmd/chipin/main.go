// Command chipin runs ChipIn, the AAuth v0.2 shopping demo.
//
//	chipin serve           ChipIn on one origin: shop (MCP resource), agent
//	                       provider, access server, static site
//	chipin agent           the shopping agent, against a running ChipIn and
//	                       a person server (Hellō by default)
//	chipin demo            everything local in one process, with a local
//	                       person server standing in for Hellō
//	chipin record-catalog  save live UCP offers for offline rehearsal
//
// Secrets come from the environment or -env-file: STRIPE_SECRET_KEY,
// CHIPIN_ENROLLMENT_SECRET.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	aauth "github.com/aauth-dev/aauth-go"
	"github.com/golang-jwt/jwt/v5"

	"github.com/gkedev/adelaide/internal/agent"
	"github.com/gkedev/adelaide/internal/hosted"
	"github.com/gkedev/adelaide/internal/keycard"
	"github.com/gkedev/adelaide/internal/keys"
	"github.com/gkedev/adelaide/internal/localps"
	"github.com/gkedev/adelaide/internal/payments"
	"github.com/gkedev/adelaide/internal/shop"
	"github.com/gkedev/adelaide/internal/spend"
	"github.com/gkedev/adelaide/internal/trust"
	"github.com/gkedev/adelaide/internal/ucp"
)

// Hello is the person server players sign in with.
const Hello = "https://person.hello.coop"

type options struct {
	origin, listen, ps, data, public string
	envFile, profile, fixture, pay   string
	budget, dailyBudget, maxOrder    float64
	balls                            int
	query, packs, brands, buy        string
	guardrail, authorizeOnly         bool
	enrollment, shopURL              string
	out                              string
	jsonOut                          bool
}

func init() {
	// Write a single audience as a JSON string, not a one-element array.
	// Both are valid JWT (RFC 7519 §4.1.3), but Hellō's auth token endpoint
	// fails on an array aud ("aud.replace is not a function").
	jwt.MarshalSingleStringAsArray = false
}

func main() {
	if len(os.Args) < 2 || strings.HasPrefix(os.Args[1], "-") {
		os.Args = append([]string{os.Args[0], "demo"}, os.Args[1:]...)
	}
	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	var o options
	fs.StringVar(&o.envFile, "env-file", ".env", "dotenv file with secrets (ignored when missing)")
	fs.StringVar(&o.origin, "origin", env("CHIPIN_ORIGIN", "https://chipin.aauth.tech"), "serve: ChipIn's public origin (its server identifier)")
	fs.StringVar(&o.listen, "listen", env("CHIPIN_LISTEN", ":8080"), "serve: listen address")
	fs.StringVar(&o.ps, "ps", env("CHIPIN_PS", Hello), "person server the agent's tokens name")
	fs.StringVar(&o.data, "data", env("CHIPIN_DATA", "data"), "serve: directory for persistent signing keys")
	fs.StringVar(&o.public, "public", env("CHIPIN_PUBLIC", "public"), "serve: static site directory")
	fs.StringVar(&o.profile, "ucp-profile", env("UCP_AGENT_PROFILE", ""), "UCP agent profile URL sent to stores (default: {origin}"+shop.UCPProfilePath+")")
	fs.StringVar(&o.fixture, "catalog-fixture", env("CHIPIN_CATALOG_FIXTURE", ""), "answer catalog searches from this recorded file")
	fs.StringVar(&o.pay, "pay", env("CHIPIN_PAY", "spt"), "payment: spt (shared payment token), card (test card), none")
	fs.Float64Var(&o.budget, "max-cost", 100, "agent: the player's max cost for the mission, USD")
	fs.StringVar(&o.packs, "case", "24", "agent: the player's case size in cans: 12, 18 or 24")
	fs.BoolVar(&o.authorizeOnly, "authorize-only", false, "agent: with -buy, stop once the order is authorized (Keycard ALLOW, auth token), without paying")
	fs.StringVar(&o.brands, "brands", "Penn,Wilson", "agent: the player's brands (Dunlop, Penn, Tecnifibre, Wilson)")
	fs.Float64Var(&o.dailyBudget, "daily-budget", envFloat("CHIPIN_DAILY_BUDGET", 0), "serve: most one person may spend per day at ChipIn, USD (0: no daily limit)")
	fs.Float64Var(&o.maxOrder, "max-order", envFloat("CHIPIN_MAX_ORDER", 150), "serve: per-order cap, USD")
	fs.IntVar(&o.balls, "balls", 24, "agent: balls the crew needs")
	fs.StringVar(&o.query, "query", "tennis balls", "agent: catalog search")
	fs.StringVar(&o.buy, "buy", "", "agent: after the shortlist, buy nothing (default), \"best\", or item N; asks when run in a terminal")
	fs.BoolVar(&o.guardrail, "show-guardrail", true, "agent: first try a product outside the mission, to show the refusal")
	fs.StringVar(&o.enrollment, "enrollment-secret", env("CHIPIN_ENROLLMENT_SECRET", ""), "agent enrollment secret")
	fs.StringVar(&o.shopURL, "shop", env("CHIPIN_SHOP_URL", "https://chipin.aauth.tech"), "agent: ChipIn origin")
	fs.StringVar(&o.out, "out", "testdata/catalog.json", "record-catalog: output file")
	fs.BoolVar(&o.jsonOut, "json", false, "agent: print the result as JSON")
	_ = fs.Parse(os.Args[2:])
	loadEnvFile(o.envFile)
	if o.enrollment == "" {
		o.enrollment = os.Getenv("CHIPIN_ENROLLMENT_SECRET")
	}

	var err error
	switch cmd {
	case "serve":
		err = serve(o)
	case "agent":
		err = runAgent(o)
	case "demo":
		err = demo(o)
	case "record-catalog":
		err = record(o)
	default:
		err = fmt.Errorf("unknown command %q (serve, agent, demo, record-catalog)", cmd)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "chipin:", err)
		os.Exit(1)
	}
}

func cents(usd float64) int64 { return int64(usd*100 + 0.5) }

// host is ChipIn on one origin.
type host struct {
	shop    *shop.Shop
	handler http.Handler
}

// newHost builds the shop, agent provider and access server on origin.
func newHost(o options, origin, ps string, stripe *payments.Stripe, hc *http.Client, insecure bool, log func(string, string)) (*host, error) {
	apKey, err := keys.LoadOrCreate(o.data, "agent-provider", aauth.AlgEd25519)
	if err != nil {
		return nil, err
	}
	asKey, err := keys.LoadOrCreate(o.data, "access-server", aauth.AlgES256)
	if err != nil {
		return nil, err
	}
	shopKey, err := keys.LoadOrCreate(o.data, "shop", aauth.AlgEd25519)
	if err != nil {
		return nil, err
	}
	domain := strings.TrimPrefix(strings.TrimPrefix(origin, "https://"), "http://")
	if insecure {
		domain = "agents.chipin.localhost"
	}
	var sh *shop.Shop
	roles, err := trust.New(trust.Config{
		Authorize: func(scope, ps, sub string) error { return sh.Authorize(scope, ps, sub) },
		Issuer:    origin, ShopURL: origin, PS: ps, AgentDomain: domain,
		APKey: apKey, ASKey: asKey,
		DailyBudgetCents: cents(o.dailyBudget), MaxOrderCents: cents(o.maxOrder),
		EnrollmentSecret: o.enrollment, HTTPClient: hc, Insecure: insecure, Log: log,
	})
	if err != nil {
		return nil, err
	}
	profile := o.profile
	if profile == "" {
		profile = origin + shop.UCPProfilePath
		if insecure {
			profile = "https://chipin.aauth.tech" + shop.UCPProfilePath
		}
	}
	catalog := &ucp.Client{Stores: ucp.DefaultStores, Profile: profile}
	if o.fixture != "" {
		if catalog.Fixture, err = ucp.LoadFixture(o.fixture); err != nil {
			return nil, fmt.Errorf("catalog fixture: %w", err)
		}
	}
	var kc *keycard.Client
	if os.Getenv("KEYCARD_CLIENT_ID") != "" && !insecure {
		kc = &keycard.Client{ZoneID: os.Getenv("KEYCARD_ZONE_ID"), ClientID: os.Getenv("KEYCARD_CLIENT_ID"),
			ClientSecret: os.Getenv("KEYCARD_CLIENT_SECRET"), Origin: origin}
	}
	sh, err = shop.New(shop.Config{
		Keycard: kc, Key: shopKey, URL: origin, AccessServer: origin, TrustedIssuers: []string{ps, origin},
		Catalog: catalog, Stripe: stripe, HTTPClient: hc, Insecure: insecure, Log: log,
	})
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	roles.Register(mux)
	sh.Register(mux)
	if key := os.Getenv("CHIPIN_BB_API_KEY"); key != "" && !insecure {
		agentsDir := ""
		if o.data != "" {
			agentsDir = filepath.Join(o.data, "agents")
		}
		hosted.New(hosted.Config{APIKey: key, ShopURL: origin, PSURL: ps, EnrollmentSecret: o.enrollment,
			KeysDir: agentsDir, Catalog: catalog, Log: log}).Register(mux)
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /robots.txt", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("User-agent: *\nDisallow: /\n"))
	})
	if o.public != "" {
		mux.Handle("/", staticSite(o.public)) // no method in the pattern: it would conflict with aauth-go's routes
	}
	// Demo service: keep every page and endpoint out of search engines.
	noindex := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Robots-Tag", "noindex, nofollow")
		mux.ServeHTTP(w, r)
	})
	return &host{shop: sh, handler: noindex}, nil
}

// staticSite serves dir, falling back to index.html like the nginx site did.
func staticSite(dir string) http.Handler {
	files := http.FileServer(http.Dir(dir))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		p := filepath.Join(dir, filepath.Clean("/"+r.URL.Path))
		if st, err := os.Stat(p); err != nil || (st.IsDir() && !exists(filepath.Join(p, "index.html"))) {
			http.ServeFile(w, r, filepath.Join(dir, "index.html"))
			return
		}
		files.ServeHTTP(w, r)
	})
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func serve(o options) error {
	if o.enrollment == "" {
		return fmt.Errorf("serve needs CHIPIN_ENROLLMENT_SECRET")
	}
	log := newLogger()
	st, _, err := stripeFor(o)
	if err != nil {
		return err
	}
	h, err := newHost(o, o.origin, o.ps, st, nil, false, log)
	if err != nil {
		return err
	}
	srv := &http.Server{Addr: o.listen, Handler: h.handler, ReadHeaderTimeout: 10 * time.Second}
	enforcer := "local rules"
	if os.Getenv("KEYCARD_CLIENT_ID") != "" {
		enforcer = "Keycard zone " + os.Getenv("KEYCARD_ZONE_ID")
	}
	log("ChipIn", fmt.Sprintf("serving %s on %s · person server %s · payment %s · missions enforced by %s · max order %s",
		o.origin, o.listen, o.ps, o.pay, enforcer, spend.Dollars(cents(o.maxOrder))))
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-errc:
		return err
	case <-sig:
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(ctx)
	}
}

func runAgent(o options) error {
	if o.enrollment == "" {
		return fmt.Errorf("agent needs -enrollment-secret (CHIPIN_ENROLLMENT_SECRET)")
	}
	log := newLogger()
	_, wallet, err := stripeFor(o)
	if err != nil {
		return err
	}
	res, err := agent.Run(context.Background(), agentConfig(o, o.shopURL, o.ps, wallet, false, log))
	if err != nil {
		return err
	}
	return report(o, res, log)
}

// demo runs ChipIn, a local person server (standing in for Hellō), and the
// agent in one process on localhost.
func demo(o options) error {
	log := newLogger()
	if o.enrollment == "" {
		o.enrollment = randomHex()
	}
	o.data = "" // fresh keys each run
	st, wallet, err := stripeFor(o)
	if err != nil {
		return err
	}
	shopLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	psLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	origin, psURL := "http://"+shopLn.Addr().String(), "http://"+psLn.Addr().String()
	hc := &http.Client{Timeout: 30 * time.Second}
	ps, err := localps.New(psURL, "G", hc, log)
	if err != nil {
		return err
	}
	psMux := http.NewServeMux()
	ps.Register(psMux)
	h, err := newHost(o, origin, psURL, st, hc, true, log)
	if err != nil {
		return err
	}
	go func() { _ = http.Serve(shopLn, h.handler) }()
	go func() { _ = http.Serve(psLn, psMux) }()
	log("Demo", fmt.Sprintf("ChipIn %s · local person server %s (stands in for Hellō) · payment %s", origin, psURL, o.pay))
	res, err := agent.Run(context.Background(), agentConfig(o, origin, psURL, wallet, true, log))
	if err != nil {
		return err
	}
	return report(o, res, log)
}

func agentConfig(o options, shopURL, ps string, wallet *payments.Stripe, insecure bool, log func(string, string)) agent.Config {
	return agent.Config{
		ShopURL: shopURL, APURL: shopURL, PSURL: ps, EnrollmentSecret: o.enrollment,
		Query: o.query, TargetBalls: o.balls, BudgetCents: cents(o.budget), TryOverBudget: o.guardrail,
		Case: o.packs, Brands: splitList(o.brands), Buy: o.buy, Decide: askPlayer, AuthorizeOnly: o.authorizeOnly,
		Wallet: wallet, Insecure: insecure, Log: log,
	}
}

// stripeFor returns the shop's Stripe client and the agent's wallet.
func stripeFor(o options) (shopStripe, wallet *payments.Stripe, err error) {
	if o.pay == "none" {
		return nil, nil, nil
	}
	key := os.Getenv("STRIPE_SECRET_KEY")
	if key == "" {
		return nil, nil, fmt.Errorf("-pay=%s needs STRIPE_SECRET_KEY (or -pay=none)", o.pay)
	}
	s, err := payments.New(key)
	if err != nil {
		return nil, nil, err
	}
	if o.pay == "spt" {
		return s, s, nil // the sandbox test helper stands in for the agent's wallet
	}
	return s, nil, nil
}

func report(o options, res *agent.Result, log func(string, string)) error {
	if o.jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(res)
	}
	if res.Order != nil {
		dash := res.Order.DashboardURL
		if dash == "" {
			dash = "no Stripe payment"
		}
		log("Demo", fmt.Sprintf("done: order %s… paid %s, %s", res.Order.OrderHash[:10], spend.Dollars(res.Order.TotalCents), dash))
	}
	return nil
}

func record(o options) error {
	profile := o.profile
	if profile == "" {
		profile = "https://chipin.aauth.tech" + shop.UCPProfilePath
	}
	c := &ucp.Client{Stores: ucp.DefaultStores, Profile: profile}
	res, err := c.Search(context.Background(), o.query)
	if err != nil {
		return err
	}
	for store, e := range res.Errors {
		fmt.Fprintf(os.Stderr, "%s: %s\n", store, e)
	}
	note := fmt.Sprintf("Recorded UCP search_catalog results for %q. Prices change: refresh before a demo.", o.query)
	if err := ucp.SaveFixture(o.out, res.Offers, note); err != nil {
		return err
	}
	fmt.Printf("saved %d offers to %s\n", len(res.Offers), o.out)
	return nil
}

func newLogger() func(role, msg string) {
	var mu sync.Mutex
	start := time.Now()
	colors := map[string]string{"Agent": "36", "Person": "33", "ChipIn AS": "35", "ChipIn AP": "35", "ChipIn": "32", "Stripe": "34", "Demo": "1"}
	fi, _ := os.Stdout.Stat()
	tty := fi != nil && fi.Mode()&os.ModeCharDevice != 0
	return func(role, msg string) {
		mu.Lock()
		defer mu.Unlock()
		label := fmt.Sprintf("%-10s", role)
		if c, ok := colors[role]; ok && tty {
			label = "\x1b[" + c + "m" + label + "\x1b[0m"
		}
		fmt.Printf("%6.1fs  %s  %s\n", time.Since(start).Seconds(), label, msg)
	}
}

func loadEnvFile(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(strings.TrimPrefix(line, "export "), "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.Trim(strings.TrimSpace(v), `"'`)
		if _, set := os.LookupEnv(k); !set {
			_ = os.Setenv(k, v)
		}
	}
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envFloat(k string, def float64) float64 {
	var f float64
	if _, err := fmt.Sscan(os.Getenv(k), &f); err == nil {
		return f
	}
	return def
}

// askPlayer asks, in a terminal, whether to buy from the shortlist. Outside
// a terminal it answers "none": nothing is bought unless -buy says so.
func askPlayer(list []agent.Choice, rec int) string {
	if fi, err := os.Stdin.Stat(); err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return "none"
	}
	hint := "a number"
	if rec >= 0 {
		hint = fmt.Sprintf("Enter for ★ %d, or a number", rec+1)
	}
	fmt.Printf("\nBuy from the shortlist? (%s, n to finish without buying): ", hint)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		// No answer (end of input, e.g. /dev/null, which also looks like a
		// character device): never treat silence as a purchase.
		fmt.Println()
		return "none"
	}
	switch line = strings.TrimSpace(line); line {
	case "":
		if rec >= 0 {
			return "best"
		}
		return "none"
	case "n", "N":
		return "none"
	}
	return line
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func randomHex() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
