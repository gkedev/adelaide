// Package hosted runs ChipIn's recommendation agent on behalf of signed-in
// BB Tennis players. BB's Worker verifies the player and calls this API with
// a shared key; each player gets their own agent key and install name, so
// each links to their own person at Hellō.
//
//	POST /api/bb/recommend          {brands, case, max_cost}  → job
//	GET  /api/bb/jobs/{id}                                     → job
//	POST /api/bb/jobs/{id}/choose   {choice: "N" | "none"}     → job
//
// A job runs the agent: Hellō sign-in when needed (the job shows the link
// and code), the mission, the shortlist; then it waits for the player's
// choice. A chosen product is authorized (ChipIn's access server and
// Keycard approve the exact order), and ChipIn creates a checkout at the
// store over UCP. The player finishes there with their own contact,
// shipping, and payment: ChipIn never sees card or address details.
package hosted

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	aauth "github.com/aauth-dev/aauth-go"

	"github.com/gkedev/adelaide/internal/agent"
	"github.com/gkedev/adelaide/internal/keys"
	"github.com/gkedev/adelaide/internal/spend"
	"github.com/gkedev/adelaide/internal/supervisor"
	"github.com/gkedev/adelaide/internal/ucp"
)

// Config configures the hosted agent.
type Config struct {
	APIKey           string // the key BB's Worker sends as X-ChipIn-Key
	ShopURL          string // ChipIn's origin
	PSURL            string // Hellō
	EnrollmentSecret string
	KeysDir          string // where player agent keys persist
	Catalog          *ucp.Client
	Log              func(role, msg string)
	// Insecure accepts http://localhost identifiers (tests only).
	Insecure bool
	// Sup, when set, serves /api/sup/*: the Supervisor demo, where the
	// agent's person server is ChipIn's own and a Supervisor decides.
	Sup *supervisor.Service
}

// Service is the hosted agent API.
type Service struct {
	cfg  Config
	mu   sync.Mutex
	jobs map[string]*Job

	window time.Time
	perIP  map[string]int
	total  int
}

// Job is one recommendation run, as the BB page sees it.
type Job struct {
	ID          string         `json:"id"`
	Status      string         `json:"status"` // searching, signin, shortlist, authorizing, checkout, done, error
	Message     string         `json:"message,omitempty"`
	SignIn      *SignIn        `json:"signin,omitempty"`
	Summary     string         `json:"summary,omitempty"`
	Shortlist   []agent.Choice `json:"shortlist"`
	Recommended int            `json:"recommended"`
	Picked      *agent.Choice  `json:"picked,omitempty"`
	Checkout    *ucp.Checkout  `json:"checkout,omitempty"`
	Steps       []string       `json:"steps"`
	// Supervision is the Supervisor demo's state: the log and any decision
	// waiting on the player.
	Supervision *supervisor.View `json:"supervision,omitempty"`
	player      string
	agentName   string
	decide      chan string
	updated     time.Time
}

// SignIn is where the player signs in with Hellō.
type SignIn struct {
	URL  string `json:"url"`
	Code string `json:"code"`
}

// New returns the service.
func New(cfg Config) *Service {
	if cfg.Log == nil {
		cfg.Log = func(string, string) {}
	}
	return &Service{cfg: cfg, jobs: map[string]*Job{}, perIP: map[string]int{}}
}

// Register adds the API routes: /api/bb/* for BB Tennis (shared key), and
// /api/try/* for the public demo page (a per-visitor cookie, rate limited).
func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/bb/recommend", s.guard(s.recommend))
	mux.HandleFunc("GET /api/bb/jobs/{id}", s.guard(s.get))
	mux.HandleFunc("POST /api/bb/jobs/{id}/choose", s.guard(s.choose))
	mux.HandleFunc("POST /api/try/recommend", s.visitor(true, s.recommend))
	mux.HandleFunc("GET /api/try/jobs/{id}", s.visitor(false, s.get))
	mux.HandleFunc("POST /api/try/jobs/{id}/choose", s.visitor(false, s.choose))
	if s.cfg.Sup != nil {
		mux.HandleFunc("POST /api/sup/recommend", s.visitor(true, s.recommend))
		mux.HandleFunc("GET /api/sup/jobs/{id}", s.visitor(false, s.get))
		mux.HandleFunc("POST /api/sup/jobs/{id}/choose", s.visitor(false, s.choose))
		mux.HandleFunc("POST /api/sup/jobs/{id}/decide", s.visitor(false, s.decide))
	}
}

// decide is the player's answer to an escalation from their Supervisor.
func (s *Service) decide(w http.ResponseWriter, r *http.Request, player string) {
	job := s.job(r.PathValue("id"), player)
	if job == nil || s.cfg.Sup == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such search"})
		return
	}
	var in struct {
		Approve bool `json:"approve"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&in)
	if err := s.cfg.Sup.Decide(r.Context(), job.agentName, in.Approve); err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, s.view(job))
}

const tryCookie = "chipin_try"

// visitor admits public demo visitors: each browser gets its own opaque id
// (so its own agent and Hellō link), and new searches are rate limited per
// IP and overall.
func (s *Service) visitor(limited bool, h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" && o != s.cfg.ShopURL {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "use the ChipIn demo page"})
			return
		}
		id := ""
		if c, err := r.Cookie(tryCookie); err == nil && len(c.Value) == 32 {
			id = c.Value
		} else {
			id = newID() + newID()[:8]
			http.SetCookie(w, &http.Cookie{Name: tryCookie, Value: id, Path: "/", MaxAge: 30 * 24 * 3600, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
		}
		if limited {
			ip := r.Header.Get("CF-Connecting-IP")
			if ip == "" {
				ip = r.RemoteAddr
			}
			if !s.allow(ip) {
				writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "Lots of searches right now. Please try again in a few minutes."})
				return
			}
		}
		h(w, r, "try:"+id)
	}
}

// allow is a fixed-window limit: 8 new searches per IP and 60 overall per hour.
func (s *Service) allow(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if now.Sub(s.window) > time.Hour {
		s.window, s.perIP, s.total = now, map[string]int{}, 0
	}
	if s.perIP[ip] >= 8 || s.total >= 60 {
		return false
	}
	s.perIP[ip]++
	s.total++
	return true
}

type handler func(w http.ResponseWriter, r *http.Request, player string)

// guard admits only BB's Worker (shared key) and names the player.
func (s *Service) guard(h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("X-ChipIn-Key")
		if s.cfg.APIKey == "" || subtle.ConstantTimeCompare([]byte(key), []byte(s.cfg.APIKey)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		player := strings.TrimSpace(r.Header.Get("X-BB-Player"))
		if player == "" || len(player) > 128 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no player"})
			return
		}
		h(w, r, player)
	}
}

func (s *Service) recommend(w http.ResponseWriter, r *http.Request, player string) {
	var in struct {
		Brands  []string `json:"brands"`
		Case    string   `json:"case"`
		MaxCost float64  `json:"max_cost"`
		// Supervisor demo only.
		Supervisor  string  `json:"supervisor"`   // policy or person
		AutoApprove float64 `json:"auto_approve"` // USD the policy approves alone
		Behaviour   string  `json:"behaviour"`    // "", overbuy, twice
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil || len(in.Brands) == 0 || in.Case == "" || in.MaxCost <= 0 || in.MaxCost > 1000 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "choose brands, a case size, and a max cost"})
		return
	}
	id := newID()
	supervised := strings.HasPrefix(r.URL.Path, "/api/sup/")
	job := &Job{ID: id, Status: "searching", Recommended: -1, player: player, decide: make(chan string, 1), updated: time.Now()}
	job.agentName = playerAgentName(player, supervised)
	var sup *supRun
	if supervised {
		switch in.Behaviour {
		case "", "overbuy", "twice":
		default:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown agent behaviour"})
			return
		}
		sup = &supRun{behaviour: in.Behaviour}
		s.cfg.Sup.Start(job.agentName, player, supervisor.Settings{Mode: in.Supervisor, AutoApproveCents: int64(in.AutoApprove*100 + 0.5)})
	}
	s.mu.Lock()
	s.gc()
	s.jobs[id] = job
	s.mu.Unlock()
	go s.run(job, in.Brands, in.Case, int64(in.MaxCost*100+0.5), sup)
	writeJSON(w, http.StatusAccepted, s.view(job))
}

func (s *Service) get(w http.ResponseWriter, r *http.Request, player string) {
	job := s.job(r.PathValue("id"), player)
	if job == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such search"})
		return
	}
	writeJSON(w, http.StatusOK, s.view(job))
}

func (s *Service) choose(w http.ResponseWriter, r *http.Request, player string) {
	job := s.job(r.PathValue("id"), player)
	if job == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such search"})
		return
	}
	var in struct {
		Choice string `json:"choice"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&in)
	s.mu.Lock()
	ready := job.Status == "shortlist"
	s.mu.Unlock()
	if !ready {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "nothing to choose yet"})
		return
	}
	select {
	case job.decide <- in.Choice:
	default:
	}
	writeJSON(w, http.StatusOK, s.view(job))
}

func (s *Service) job(id, player string) *Job {
	s.mu.Lock()
	defer s.mu.Unlock()
	j := s.jobs[id]
	if j == nil || j.player != player {
		return nil
	}
	return j
}

// view is a consistent copy of a job.
func (s *Service) view(j *Job) Job {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := *j
	// Lists are always JSON arrays, never null: the BB page reads .length.
	c.Steps = append(make([]string, 0, len(j.Steps)), j.Steps...)
	if s.cfg.Sup != nil && strings.HasPrefix(j.agentName, "sup-") {
		c.Supervision = s.cfg.Sup.View(j.agentName)
	}
	if c.Shortlist == nil {
		c.Shortlist = []agent.Choice{}
	}
	return c
}

func (s *Service) update(j *Job, f func(*Job)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f(j)
	j.updated = time.Now()
}

// supRun is a supervised run's extras.
type supRun struct{ behaviour string }

// run is one recommendation, start to finish.
func (s *Service) run(job *Job, brands []string, caseSize string, maxCents int64, sup *supRun) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	name := job.agentName
	key, err := keys.LoadOrCreate(s.cfg.KeysDir, name, aauth.AlgEd25519)
	if err != nil {
		s.fail(job, err)
		return
	}
	step := func(role, msg string) {
		s.cfg.Log(role, msg)
		if role == "Agent" || role == "Person" {
			s.update(job, func(j *Job) { j.Steps = append(j.Steps, msg) })
		}
	}
	cfg := agent.Config{
		ShopURL: s.cfg.ShopURL, APURL: s.cfg.ShopURL, PSURL: s.cfg.PSURL, EnrollmentSecret: s.cfg.EnrollmentSecret,
		Key: key, AgentName: name,
		Case: caseSize, Brands: brands, BudgetCents: maxCents, TargetBalls: 24,
		AuthorizeOnly: true, Log: step, Insecure: s.cfg.Insecure,
		OnInteraction: func(url, code string) {
			s.update(job, func(j *Job) { j.Status, j.SignIn = "signin", &SignIn{URL: url, Code: code} })
		},
		Decide: func(list []agent.Choice, rec int) string {
			s.update(job, func(j *Job) { j.Status, j.SignIn, j.Shortlist, j.Recommended = "shortlist", nil, list, rec })
			select {
			case c := <-job.decide:
				if c != "" && c != "none" {
					s.update(job, func(j *Job) { j.Status = "authorizing" })
				}
				return c
			case <-time.After(20 * time.Minute):
				return "none"
			}
		},
	}
	if sup != nil {
		cfg.PSURL, cfg.Behaviour = s.cfg.Sup.Issuer(), sup.behaviour
		cfg.Mission = fmt.Sprintf("Buy tennis balls for my crew: %s, %s-can case, at most %s.", strings.Join(brands, " or "), caseSize, spend.Dollars(maxCents))
		cfg.OnMission = func(s256 string) { s.cfg.Sup.MissionApproved(name, s256) }
	}
	res, err := agent.Run(ctx, cfg)
	if err != nil {
		s.fail(job, err)
		return
	}
	if res.Picked == nil {
		// Reviewed without buying, or nothing fits.
		s.update(job, func(j *Job) {
			j.Status, j.Shortlist, j.Recommended = "done", res.Shortlist, res.Recommended
			if len(res.Shortlist) == 0 {
				j.Message = "No products meet those choices right now. Try another brand, case size or max cost."
			}
		})
		return
	}
	pick := res.Picked
	co, err := s.cfg.Catalog.CreateCheckout(ctx, pick.Store, pick.VariantID, pick.Quantity)
	if err != nil {
		s.fail(job, fmt.Errorf("Keycard approved it, but %s did not open a checkout: %w", pick.Store, err))
		return
	}
	s.cfg.Log("ChipIn", fmt.Sprintf("store checkout at %s for %s: %s", co.Store, spend.Dollars(co.TotalCents), co.Status))
	s.update(job, func(j *Job) { j.Status, j.Picked, j.Checkout = "checkout", pick, co })
}

func (s *Service) fail(job *Job, err error) {
	s.cfg.Log("ChipIn", "hosted agent: "+err.Error())
	msg := err.Error()
	if i := strings.Index(msg, "aauth: "); i >= 0 {
		msg = msg[i+len("aauth: "):]
	}
	s.update(job, func(j *Job) { j.Status, j.Message, j.SignIn = "error", msg, nil })
}

// gc drops jobs idle for over an hour (callers hold s.mu).
func (s *Service) gc() {
	for id, j := range s.jobs {
		if time.Since(j.updated) > time.Hour {
			delete(s.jobs, id)
		}
	}
}

// playerAgentName is a stable, opaque install name per player.
// Supervised installs are "sup-…": the agent provider names ChipIn's own
// person server for them.
func playerAgentName(player string, supervised bool) string {
	prefix := "bb-"
	if strings.HasPrefix(player, "try:") {
		prefix = "web-"
	}
	seed := "bb-player:" + player
	if supervised {
		prefix, seed = "sup-", "sup-player:"+player
	}
	sum := sha256.Sum256([]byte(seed))
	return prefix + hex.EncodeToString(sum[:])[:16]
}

func newID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
