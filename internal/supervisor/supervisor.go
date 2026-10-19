// Package supervisor is ChipIn's own person server with a Supervisor, for
// the /supervisor/ demo (AAuth draft -11 §4 "Supervisor", §8 missions).
//
// Hellō, the person server of the main demo, has no missions. Here the
// agent's token names this PS instead: the agent proposes a mission, and
// every act under it (the mission itself, each purchase) is evaluated by
// the Supervisor against the mission's intent and the log so far. The
// Supervisor is either the person ("you decide everything") or a
// supervision server applying the parent's standing policy, which answers
// one of four ways:
//
//   - approve: within policy, the PS issues the token (and federates the
//     purchase to ChipIn's access server, where Keycard still applies);
//   - deny: against the mission's intent, refused at the PS;
//   - escalate: outside what the policy may decide alone, deferred
//     (requirement=approval) until the person decides on the demo page;
//   - steer: sent back to the agent as a clarification question
//     (requirement=clarification); the agent withdraws and corrects.
//
// The supervision protocol between a PS and a supervision server is not
// specified yet (a companion specification is TBD); here it is in process.
package supervisor

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	aauth "github.com/aauth-dev/aauth-go"
	"github.com/aauth-dev/aauth-go/accessserver"
	"github.com/aauth-dev/aauth-go/personserver"

	"github.com/gkedev/adelaide/internal/spend"
)

// Supervisor modes.
const (
	ModePolicy = "policy" // the parent's standing policy (a supervision server)
	ModePerson = "person" // the person decides every act
)

// Verdicts in the log.
const (
	Approve  = "approve"
	Deny     = "deny"
	Escalate = "escalate"
	Steer    = "steer"
)

// Settings are a session's supervision choices.
type Settings struct {
	Mode string `json:"mode"`
	// AutoApproveCents is the most the policy approves without the person.
	AutoApproveCents int64 `json:"auto_approve_cents"`
}

// Entry is one line of the supervision log.
type Entry struct {
	Time    time.Time `json:"time"`
	Act     string    `json:"act"`     // what was asked: "Mission", "Purchase", "Identity", "Keycard mission"
	Detail  string    `json:"detail"`  // the request, as the agent or resource put it
	Verdict string    `json:"verdict"` // approve, deny, escalate, steer
	By      string    `json:"by"`      // who decided
	Reason  string    `json:"reason,omitempty"`
}

// Escalation is a decision waiting on the person.
type Escalation struct {
	ID     string `json:"id"`
	Act    string `json:"act"`
	Detail string `json:"detail"`
	Reason string `json:"reason"`
}

// View is what the demo page shows.
type View struct {
	Mode       string      `json:"mode"`
	Supervisor string      `json:"supervisor"`
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
	bought    []string // approved purchases, for the policy's context
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
	if st.Mode != ModePerson {
		st.Mode = ModePolicy
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[agentName] = &session{person: person, settings: st}
}

// View returns the session's supervision state.
func (s *Service) View(agentName string) *View {
	s.mu.Lock()
	defer s.mu.Unlock()
	ss := s.sessions[agentName]
	if ss == nil {
		return nil
	}
	v := &View{Mode: ss.settings.Mode, Supervisor: supervisorName(ss.settings.Mode), Mission: ss.mission, MissionID: ss.missionID,
		Log: append([]Entry{}, ss.log...)}
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
		err = s.PS.Deny(ctx, e.ID, "The person declined: "+e.Detail)
	}
	if err != nil {
		return err
	}
	verdict, reason := Approve, "you approved"
	if !approve {
		verdict, reason = Deny, "you declined"
	}
	s.mu.Lock()
	if approve && e.Act == "Purchase" {
		ss.bought = append(ss.bought, e.Detail)
	}
	s.mu.Unlock()
	s.entry(agentName, Entry{Act: e.Act, Detail: e.Detail, Verdict: verdict, By: "You", Reason: reason})
	return nil
}

// End drops a session.
func (s *Service) End(agentName string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, agentName)
}

func supervisorName(mode string) string {
	if mode == ModePerson {
		return "You"
	}
	return "Parent’s policy (supervision server)"
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
func (s *Service) escalate(name string, ss *session, act, detail, reason string) personserver.Decision {
	s.mu.Lock()
	ss.nextAsk = &Escalation{Act: act, Detail: detail, Reason: reason}
	s.mu.Unlock()
	s.entry(name, Entry{Act: act, Detail: detail, Verdict: Escalate, By: supervisorName(ss.settings.Mode), Reason: reason})
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

func (s *Service) decideMission(_ context.Context, r *personserver.MissionRequest) (personserver.Decision, error) {
	name, ss := s.sessionFor(r.Agent)
	if ss == nil {
		return personserver.Deny("no supervised session for this agent"), nil
	}
	if r.Kind != personserver.KindMissionProposal {
		s.entry(name, Entry{Act: "Mission", Detail: "mission " + string(r.Kind), Verdict: Approve, By: supervisorName(ss.settings.Mode)})
		return personserver.Allow(personserver.Grant{Person: ss.person}), nil
	}
	desc := r.Proposal.Description
	s.mu.Lock()
	ss.mission = desc
	s.mu.Unlock()
	if ss.settings.Mode == ModePerson {
		return s.escalate(name, ss, "Mission", desc, "you supervise every decision"), nil
	}
	if !strings.Contains(strings.ToLower(desc), "tennis balls") {
		s.entry(name, Entry{Act: "Mission", Detail: desc, Verdict: Deny, By: supervisorName(ss.settings.Mode), Reason: "the standing policy covers tennis balls only"})
		return personserver.Deny("the standing policy covers tennis balls only"), nil
	}
	s.entry(name, Entry{Act: "Mission", Detail: desc, Verdict: Approve, By: supervisorName(ss.settings.Mode), Reason: "tennis balls for the crew: within the standing policy"})
	return personserver.Allow(personserver.Grant{Person: ss.person}), nil
}

// MissionApproved records the approved mission's identifier for display.
func (s *Service) MissionApproved(agentName, s256 string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ss := s.sessions[agentName]; ss != nil {
		ss.missionID = s256
	}
}

var quantity = regexp.MustCompile(`^Buy (\d+) × `)

// Justification writes the purchase justification the agent sends (and the
// policy reads, as the agent's claim): "Buy N × title (pack) at store".
func Justification(qty int, title, pack, store string) string {
	return fmt.Sprintf("Buy %d × %s (%s) at %s", qty, title, pack, store)
}

func (s *Service) decideToken(_ context.Context, r *personserver.TokenRequest) (personserver.Decision, error) {
	name, ss := s.sessionFor(r.Agent)
	if ss == nil {
		return personserver.Deny("no supervised session for this agent"), nil
	}
	g := personserver.Grant{}
	if r.Person == "" {
		g.Person = ss.person
	}
	by := supervisorName(ss.settings.Mode)
	if r.Kind == personserver.KindPersonToken {
		s.entry(name, Entry{Act: "Identity", Detail: "person token for " + r.Resource, Verdict: Approve, By: "ChipIn PS", Reason: "the agent acts for you under the mission"})
		return personserver.Allow(g), nil
	}
	amount, isPayment := spend.AmountFromScope(r.Scope)
	if !isPayment {
		// Publishing the mission to Keycard (mission:approve): the person
		// already approved the mission it implements.
		s.entry(name, Entry{Act: "Keycard mission", Detail: "publish your choices to Keycard", Verdict: Approve, By: by, Reason: "implements the approved mission"})
		return personserver.Allow(g), nil
	}
	if r.Mission == nil {
		s.entry(name, Entry{Act: "Purchase", Detail: spend.Dollars(amount), Verdict: Deny, By: "ChipIn PS", Reason: "no mission"})
		return personserver.Deny("purchases need an approved mission"), nil
	}
	claim := r.Hints.Justification
	if claim == "" {
		claim = "an order"
	}
	detail := fmt.Sprintf("%s, %s", claim, spend.Dollars(amount))
	if ss.settings.Mode == ModePerson {
		return s.escalate(name, ss, "Purchase", detail, "you supervise every decision"), nil
	}
	s.mu.Lock()
	bought := append([]string{}, ss.bought...)
	s.mu.Unlock()
	switch qty := justifiedQuantity(claim); {
	case len(bought) > 0:
		reason := "the mission is already covered: " + bought[0]
		s.entry(name, Entry{Act: "Purchase", Detail: detail, Verdict: Deny, By: by, Reason: reason})
		return personserver.Deny(reason), nil
	case qty > 1:
		reason := fmt.Sprintf("%d cases is more than the crew needs; one case covers the mission", qty)
		s.entry(name, Entry{Act: "Purchase", Detail: detail, Verdict: Steer, By: by, Reason: reason})
		return personserver.DeferClarification(reason+". Reduce the order to 1 case?", "Reduce to 1 case", "Withdraw"), nil
	case amount > ss.settings.AutoApproveCents:
		return s.escalate(name, ss, "Purchase", detail, fmt.Sprintf("over the %s the policy approves alone", spend.Dollars(ss.settings.AutoApproveCents))), nil
	}
	s.entry(name, Entry{Act: "Purchase", Detail: detail, Verdict: Approve, By: by,
		Reason: fmt.Sprintf("one case, within the %s auto-approve limit", spend.Dollars(ss.settings.AutoApproveCents))})
	s.mu.Lock()
	ss.bought = append(ss.bought, detail)
	s.mu.Unlock()
	return personserver.Allow(g), nil
}

func justifiedQuantity(j string) int {
	m := quantity.FindStringSubmatch(j)
	if m == nil {
		return 1
	}
	n, _ := strconv.Atoi(m[1])
	return n
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
