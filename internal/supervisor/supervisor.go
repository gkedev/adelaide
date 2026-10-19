// Package supervisor is ChipIn's own person server with a Supervisor, for
// the /supervisor/ demo (AAuth draft -11 §4 "Supervisor", §8 missions).
//
// Hellō, the person server of the main demo, has no missions. Here the
// agent's token names this PS instead. The Supervisor is the control plane,
// authorization only:
//
//   - inputs: the mission, the mission log, the person's policy, and the
//     resource's requirement (the scope ChipIn signs into its resource
//     token: amount, case count, order hash);
//   - outputs: allow, deny, clarify (a question back to the agent; it
//     withdraws and corrects), or escalate (deferred, requirement=approval,
//     until the person decides).
//
// Per-act approval goes away; the accountable person does not: the person
// approves the mission and their policy once, and is reached again only on
// escalation. Injected content cannot reach the decision: the agent's
// justification is recorded and shown, never read by the policy.
//
// The protocol between a PS and a supervision server is not specified yet
// (a companion specification is TBD); here the Supervisor is in process.
package supervisor

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	aauth "github.com/aauth-dev/aauth-go"
	"github.com/aauth-dev/aauth-go/accessserver"
	"github.com/aauth-dev/aauth-go/personserver"

	"github.com/gkedev/adelaide/internal/spend"
)

// Verdicts in the log. Issued marks a person server event that is not a
// supervision decision (identity).
const (
	Allow    = "allow"
	Deny     = "deny"
	Clarify  = "clarify"
	Escalate = "escalate"
	Issued   = "issued"
)

// Who decides.
const (
	BySupervisor = "Supervisor (parent’s policy)"
	ByPerson     = "You"
	ByPS         = "Person server"
)

// Settings are the person's policy for a session.
type Settings struct {
	// AutoApproveCents is the most the Supervisor allows without the person.
	AutoApproveCents int64 `json:"auto_approve_cents"`
}

// Entry is one line of the supervision log.
type Entry struct {
	Time    time.Time `json:"time"`
	Act     string    `json:"act"`     // Mission, Purchase, Keycard mission, Identity
	Detail  string    `json:"detail"`  // the act, from the resource's requirement
	Verdict string    `json:"verdict"` // allow, deny, clarify, escalate, issued
	By      string    `json:"by"`
	Reason  string    `json:"reason,omitempty"`
	// Inputs is what the decision was made from.
	Inputs string `json:"inputs,omitempty"`
	// AgentSays is the agent's justification: recorded and shown, never an
	// input to the decision.
	AgentSays string `json:"agent_says,omitempty"`
}

// Escalation is a decision waiting on the person.
type Escalation struct {
	ID        string `json:"id"`
	Act       string `json:"act"`
	Detail    string `json:"detail"`
	Reason    string `json:"reason"`
	AgentSays string `json:"agent_says,omitempty"`
}

// View is what the demo page shows.
type View struct {
	Policy     string      `json:"policy"`
	Mission    string      `json:"mission,omitempty"`
	MissionID  string      `json:"mission_s256,omitempty"`
	Log        []Entry     `json:"log"`
	Escalation *Escalation `json:"escalation,omitempty"`
}

type session struct {
	person    string
	settings  Settings
	mission   string
	missionID string
	log       []Entry
	pending   *Escalation
	nextAsk   *Escalation // set by a decision that escalates, claimed by Notify
}

// Service is the person server and its Supervisor.
type Service struct {
	PS     *personserver.Server
	issuer string
	log    func(role, msg string)

	mu       sync.Mutex
	sessions map[string]*session // by agent name
}

// New builds the PS at issuer. hc reaches the access servers it federates
// to; insecure accepts http://localhost identifiers (tests only).
func New(issuer string, hc *http.Client, insecure bool, log func(role, msg string)) (*Service, error) {
	if log == nil {
		log = func(string, string) {}
	}
	key, err := aauth.GenerateKey(aauth.AlgEd25519)
	if err != nil {
		return nil, err
	}
	subjectKey := make([]byte, 32)
	if _, err := rand.Read(subjectKey); err != nil {
		return nil, err
	}
	s := &Service{issuer: issuer, log: log, sessions: map[string]*session{}}
	fed := &federator{}
	s.PS, err = personserver.New(personserver.Config{
		HTTPClient: hc, Issuer: issuer, Key: key, SubjectKey: subjectKey,
		Store:                       personserver.NewMemoryStore(),
		Decider:                     personserver.DeciderFunc(s.decideToken),
		MissionApprover:             personserver.MissionApproverFunc(s.decideMission),
		Federator:                   fed,
		Notify:                      s.notify,
		Metadata:                    aauth.ServerMetadata{Name: "ChipIn Person Server (Supervisor demo)"},
		InsecureSkipIdentifierCheck: insecure,
	})
	if err != nil {
		return nil, err
	}
	fed.f = accessserver.NewClient(s.PS.Signer(), hc)
	return s, nil
}

// Issuer is the PS's identifier, the ps the supervised agents' tokens name.
func (s *Service) Issuer() string { return s.issuer }

// Start opens a session for an agent install acting for person.
func (s *Service) Start(agentName, person string, st Settings) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[agentName] = &session{person: person, settings: st}
}

func policyText(st Settings) string {
	return fmt.Sprintf("allow one case per mission up to %s; escalate above; clarify oversized orders; deny repeat purchases", spend.Dollars(st.AutoApproveCents))
}

// View returns the session's supervision state.
func (s *Service) View(agentName string) *View {
	s.mu.Lock()
	defer s.mu.Unlock()
	ss := s.sessions[agentName]
	if ss == nil {
		return nil
	}
	v := &View{Policy: policyText(ss.settings), Mission: ss.mission, MissionID: ss.missionID, Log: append([]Entry{}, ss.log...)}
	if ss.pending != nil {
		e := *ss.pending
		v.Escalation = &e
	}
	return v
}

// Decide is the person's answer to the session's escalation.
func (s *Service) Decide(ctx context.Context, agentName string, approve bool) error {
	s.mu.Lock()
	ss := s.sessions[agentName]
	if ss == nil || ss.pending == nil {
		s.mu.Unlock()
		return fmt.Errorf("nothing is waiting for you")
	}
	e := *ss.pending
	ss.pending = nil
	person := ss.person
	s.mu.Unlock()
	var err error
	if approve {
		err = s.PS.Approve(ctx, e.ID, personserver.Grant{Person: person})
	} else {
		err = s.PS.Deny(ctx, e.ID, "declined by the person")
	}
	if err != nil {
		return err
	}
	verdict, reason := Allow, "you approved"
	if !approve {
		verdict, reason = Deny, "you declined"
	}
	s.entry(agentName, Entry{Act: e.Act, Detail: e.Detail, Verdict: verdict, By: ByPerson, Reason: reason})
	return nil
}

func (s *Service) entry(agentName string, e Entry) {
	e.Time = time.Now()
	s.mu.Lock()
	if ss := s.sessions[agentName]; ss != nil {
		ss.log = append(ss.log, e)
	}
	s.mu.Unlock()
	msg := fmt.Sprintf("%s %s: %s (%s)", strings.ToUpper(e.Verdict), e.Act, e.Detail, e.By)
	if e.Reason != "" {
		msg += ": " + e.Reason
	}
	s.log("Supervisor", msg)
}

// sessionFor finds the session of the agent that signed a request.
func (s *Service) sessionFor(agent *aauth.AgentClaims) (string, *session) {
	if agent == nil {
		return "", nil
	}
	id, err := aauth.ParseAgentIdentifier(agent.Subject)
	if err != nil {
		return "", nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return id.Name, s.sessions[id.Name]
}

// escalate defers to the person: the page shows the request, and
// [Service.Decide] resolves it.
func (s *Service) escalate(name string, ss *session, e Entry) personserver.Decision {
	s.mu.Lock()
	ss.nextAsk = &Escalation{Act: e.Act, Detail: e.Detail, Reason: e.Reason, AgentSays: e.AgentSays}
	s.mu.Unlock()
	e.Verdict = Escalate
	s.entry(name, e)
	return personserver.DeferApproval()
}

// notify claims a new pending request for the escalation that created it.
func (s *Service) notify(_ context.Context, p *personserver.Pending) {
	if p.State != personserver.StatePending || p.Requirement != aauth.RequirementApproval {
		return
	}
	id, err := aauth.ParseAgentIdentifier(p.Agent.Subject)
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ss := s.sessions[id.Name]; ss != nil && ss.nextAsk != nil {
		e := *ss.nextAsk
		e.ID = p.ID
		ss.pending, ss.nextAsk = &e, nil
	}
}

// decideMission: the accountable person approves the mission and their
// policy once. Updates and completions within it are the Supervisor's.
func (s *Service) decideMission(_ context.Context, r *personserver.MissionRequest) (personserver.Decision, error) {
	name, ss := s.sessionFor(r.Agent)
	if ss == nil {
		return personserver.Deny("no supervised session for this agent"), nil
	}
	if r.Kind != personserver.KindMissionProposal {
		s.entry(name, Entry{Act: "Mission", Detail: "mission " + string(r.Kind), Verdict: Allow, By: BySupervisor})
		return personserver.Allow(personserver.Grant{Person: ss.person}), nil
	}
	desc := r.Proposal.Description
	s.mu.Lock()
	ss.mission = desc
	st := ss.settings
	s.mu.Unlock()
	return s.escalate(name, ss, Entry{Act: "Mission", Detail: desc + " Policy: " + policyText(st) + ".",
		By: BySupervisor, Reason: "a new mission and its policy need the accountable person, once"}), nil
}

// MissionApproved records the approved mission's identifier for display.
func (s *Service) MissionApproved(agentName, s256 string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ss := s.sessions[agentName]; ss != nil {
		ss.missionID = s256
	}
}

// priorPurchases are the purchases the mission log shows authorized: auth
// tokens issued under the mission for an order.
func (s *Service) priorPurchases(ctx context.Context, s256 string) []string {
	entries, err := s.PS.MissionLog(ctx, s256)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.Kind != personserver.LogTokenRequest {
			continue
		}
		var b struct {
			Type  string `json:"type"`
			Scope string `json:"scope"`
		}
		if json.Unmarshal(e.Body, &b) != nil || b.Type != "auth_token" {
			continue
		}
		if amount, ok := spend.AmountFromScope(b.Scope); ok {
			out = append(out, orderText(amount, b.Scope))
		}
	}
	return out
}

// orderText describes an order from its scope alone.
func orderText(amount int64, scope string) string {
	t := spend.Dollars(amount)
	if n, ok := spend.CasesFromScope(scope); ok {
		t += fmt.Sprintf(" · %d case%s", n, plural(n))
	}
	if h := spend.OrderFromScope(scope); h != "" {
		t += " · order " + short(h)
	}
	return t
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func short(h string) string {
	if len(h) > 10 {
		return h[:10] + "…"
	}
	return h
}

func (s *Service) decideToken(ctx context.Context, r *personserver.TokenRequest) (personserver.Decision, error) {
	name, ss := s.sessionFor(r.Agent)
	if ss == nil {
		return personserver.Deny("no supervised session for this agent"), nil
	}
	g := personserver.Grant{}
	if r.Person == "" {
		g.Person = ss.person
	}
	if r.Kind == personserver.KindPersonToken {
		// Identity, not authorization: the PS's own event.
		s.entry(name, Entry{Act: "Identity", Detail: "person token for " + r.Resource, Verdict: Issued, By: ByPS})
		return personserver.Allow(g), nil
	}
	amount, isPayment := spend.AmountFromScope(r.Scope)
	if !isPayment {
		s.entry(name, Entry{Act: "Keycard mission", Detail: "publish your choices to Keycard", Verdict: Allow, By: BySupervisor,
			Reason: "implements the approved mission", Inputs: "mission · requirement scope"})
		return personserver.Allow(g), nil
	}
	if r.Mission == nil {
		s.entry(name, Entry{Act: "Purchase", Detail: spend.Dollars(amount), Verdict: Deny, By: BySupervisor, Reason: "no mission"})
		return personserver.Deny("purchases need an approved mission"), nil
	}
	// The decision's inputs: mission, log, policy, requirement. Nothing
	// the agent wrote is among them.
	cases, _ := spend.CasesFromScope(r.Scope)
	prior := s.priorPurchases(ctx, r.Mission.S256)
	s.mu.Lock()
	limit := ss.settings.AutoApproveCents
	s.mu.Unlock()
	e := Entry{Act: "Purchase", Detail: orderText(amount, r.Scope), By: BySupervisor, AgentSays: r.Hints.Justification,
		Inputs: fmt.Sprintf("requirement (signed by ChipIn): %s · log: %d prior purchase%s · policy: up to %s · mission %s",
			orderText(amount, r.Scope), len(prior), plural(len(prior)), spend.Dollars(limit), short(r.Mission.S256))}
	switch {
	case len(prior) > 0:
		e.Verdict, e.Reason = Deny, "the mission log shows it is covered: "+prior[0]
		s.entry(name, e)
		return personserver.Deny(e.Reason), nil
	case cases > 1:
		e.Verdict, e.Reason = Clarify, fmt.Sprintf("%d cases; the policy allows one case per mission", cases)
		s.entry(name, e)
		return personserver.DeferClarification(e.Reason+". Reduce the order to 1 case?", "Reduce to 1 case", "Withdraw"), nil
	case amount > limit:
		e.Reason = fmt.Sprintf("over the %s the policy allows alone", spend.Dollars(limit))
		return s.escalate(name, ss, e), nil
	}
	e.Verdict, e.Reason = Allow, fmt.Sprintf("one case, within %s, first purchase of the mission", spend.Dollars(limit))
	s.entry(name, e)
	return personserver.Allow(g), nil
}

type federator struct{ f personserver.Federator }

func (l *federator) Federate(ctx context.Context, r *personserver.FederationRequest) (*personserver.FederationResponse, error) {
	return l.f.Federate(ctx, r)
}
func (l *federator) Poll(ctx context.Context, u string) (*personserver.FederationResponse, error) {
	return l.f.Poll(ctx, u)
}
func (l *federator) Answer(ctx context.Context, u string, body any) error {
	return l.f.Answer(ctx, u, body)
}
