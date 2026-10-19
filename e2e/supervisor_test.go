package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gkedev/adelaide/internal/agent"
	"github.com/gkedev/adelaide/internal/hosted"
	"github.com/gkedev/adelaide/internal/supervisor"
)

// supervised runs the agent under ChipIn's PS and its Supervisor; the
// person approves each escalation (the mission first).
func (d *deployment) supervised(t *testing.T, name string, st supervisor.Settings, behaviour string) (*agent.Result, error) {
	d.sup.Start(name, "player-1", st)
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case <-done:
				return
			case <-time.After(20 * time.Millisecond):
			}
			if v := d.sup.View(name); v != nil && v.Escalation != nil {
				_ = d.sup.Decide(context.Background(), name, true)
			}
		}
	}()
	return d.run(t, func(c *agent.Config) {
		c.PSURL, c.AgentName, c.Behaviour = d.sup.Issuer(), name, behaviour
		c.Mission = "Buy tennis balls for my crew: Penn, 12-can case, at most $60.00."
		c.OnMission = func(s string) { d.sup.MissionApproved(name, s) }
		c.TryOverBudget, c.AuthorizeOnly = false, true
	})
}

func verdicts(v *supervisor.View) string {
	var out []string
	for _, e := range v.Log {
		out = append(out, e.Act+":"+e.Verdict)
	}
	return strings.Join(out, " ")
}

// The accountable person approves the mission once; the purchase within
// policy is the Supervisor's alone.
func TestSupervisorAllows(t *testing.T) {
	d := deploy(t, 15000)
	res, err := d.supervised(t, "sup-allow", supervisor.Settings{AutoApproveCents: 10000}, "")
	if err != nil {
		t.Fatal(err)
	}
	v := d.sup.View("sup-allow")
	if !res.Authorized || v.MissionID == "" || !strings.HasPrefix(verdicts(v), "Mission:escalate Mission:allow") || !strings.HasSuffix(verdicts(v), "Purchase:allow") {
		t.Fatalf("authorized %v log %s", res.Authorized, verdicts(v))
	}
	last := v.Log[len(v.Log)-1]
	if last.By != supervisor.BySupervisor || !strings.Contains(last.Inputs, "1 case") || !strings.Contains(last.Inputs, "0 prior purchases") {
		t.Fatalf("last entry %+v", last)
	}
	if !strings.Contains(d.trace.String(), "ALLOW $54.95 for order") {
		t.Error("ChipIn AS did not see the purchase")
	}
}

func TestSupervisorClarifies(t *testing.T) {
	d := deploy(t, 15000)
	res, err := d.supervised(t, "sup-clarify", supervisor.Settings{AutoApproveCents: 20000}, "overbuy")
	if err != nil {
		t.Fatal(err)
	}
	v := d.sup.View("sup-clarify")
	if !res.Authorized || res.Picked.Quantity != 1 || !strings.HasSuffix(verdicts(v), "Purchase:clarify Purchase:allow") {
		t.Fatalf("picked %+v log %s", res.Picked, verdicts(v))
	}
}

// TestInjectionCannotReachTheDecision: the agent's justification claims one
// pre-approved case; the requirement ChipIn signed says two. The
// Supervisor decides from the requirement.
func TestInjectionCannotReachTheDecision(t *testing.T) {
	d := deploy(t, 15000)
	res, err := d.supervised(t, "sup-inject", supervisor.Settings{AutoApproveCents: 20000}, "inject")
	if err != nil {
		t.Fatal(err)
	}
	v := d.sup.View("sup-inject")
	var hit *supervisor.Entry
	for i := range v.Log {
		if v.Log[i].Verdict == supervisor.Clarify {
			hit = &v.Log[i]
		}
	}
	if hit == nil || !strings.Contains(hit.AgentSays, "Ignore your policy") || !strings.Contains(hit.Detail, "2 cases") || res.Picked.Quantity != 1 {
		t.Fatalf("log %s entry %+v", verdicts(v), hit)
	}
}

func TestSupervisorDeniesSecondPurchase(t *testing.T) {
	d := deploy(t, 15000)
	d.catalog.Stores[0].Endpoint = fakeStore(t,
		product("te1", "Penn Championship Extra Duty 12 Cans", 5495),
		product("te4", "Penn Tour Extra Duty 12 Cans", 5795))
	res, err := d.supervised(t, "sup-twice", supervisor.Settings{AutoApproveCents: 20000}, "twice")
	if err != nil {
		t.Fatal(err)
	}
	v := d.sup.View("sup-twice")
	if !res.Authorized || len(res.Denials) != 1 || !strings.HasSuffix(verdicts(v), "Purchase:allow Purchase:deny") || !strings.Contains(v.Log[len(v.Log)-1].Reason, "mission log") {
		t.Fatalf("denials %q log %s", res.Denials, verdicts(v))
	}
}

func TestSupervisorEscalates(t *testing.T) {
	d := deploy(t, 15000)
	res, err := d.supervised(t, "sup-escalate", supervisor.Settings{AutoApproveCents: 3000}, "")
	if err != nil {
		t.Fatal(err)
	}
	v := d.sup.View("sup-escalate")
	if !res.Authorized || !strings.HasSuffix(verdicts(v), "Purchase:escalate Purchase:allow") || v.Log[len(v.Log)-1].By != supervisor.ByPerson {
		t.Fatalf("log %s", verdicts(v))
	}
}

// TestHostedSupervisorFlow: the /supervisor/ page's API. The player
// approves the mission and policy once; the purchase is the Supervisor's.
func TestHostedSupervisorFlow(t *testing.T) {
	d := deploy(t, 15000)
	svc := hosted.New(hosted.Config{ShopURL: d.shopURL, PSURL: d.psURL, EnrollmentSecret: "install-7",
		Catalog: d.catalog, Log: d.log, Insecure: true, Sup: d.sup})
	mux := http.NewServeMux()
	svc.Register(mux)
	api := httptest.NewServer(mux)
	t.Cleanup(api.Close)
	cookie := ""
	var job hosted.Job
	call := func(method, path, body string) {
		t.Helper()
		req, _ := http.NewRequest(method, api.URL+path, strings.NewReader(body))
		if cookie != "" {
			req.Header.Set("Cookie", cookie)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		if c := res.Cookies(); len(c) > 0 {
			cookie = c[0].Name + "=" + c[0].Value
		}
		if res.StatusCode >= 300 {
			t.Fatalf("%s %s: %d", method, path, res.StatusCode)
		}
		job = hosted.Job{}
		_ = json.NewDecoder(res.Body).Decode(&job)
	}
	waitFor := func(what string, ok func() bool) {
		t.Helper()
		for i := 0; i < 200 && !ok() && job.Status != "error"; i++ {
			time.Sleep(50 * time.Millisecond)
			call("GET", "/api/sup/jobs/"+job.ID, "")
		}
		if !ok() {
			t.Fatalf("waiting for %s: status %q %s\n%s", what, job.Status, job.Message, d.trace.String())
		}
	}
	escalated := func() bool { return job.Supervision != nil && job.Supervision.Escalation != nil }
	call("POST", "/api/sup/recommend", `{"brands":["Penn"],"case":"12","max_cost":60,"auto_approve":80}`)
	waitFor("mission escalation", escalated)
	if job.Supervision.Escalation.Act != "Mission" || !strings.Contains(job.Supervision.Escalation.Detail, "Policy: allow one case") {
		t.Fatalf("escalation %+v", job.Supervision)
	}
	call("POST", "/api/sup/jobs/"+job.ID+"/decide", `{"approve":true}`)
	waitFor("shortlist", func() bool { return job.Status == "shortlist" })
	call("POST", "/api/sup/jobs/"+job.ID+"/choose", `{"choice":"1"}`)
	waitFor("checkout", func() bool { return job.Status == "checkout" })
	if got := verdicts(job.Supervision); !strings.HasPrefix(got, "Mission:escalate Mission:allow") || !strings.HasSuffix(got, "Purchase:allow") || strings.Count(got, "escalate") != 1 || job.Supervision.MissionID == "" {
		t.Fatalf("log %s", got)
	}
}

// TestRepeatRunFreshCart: a second run by the same player starts with an
// empty cart; lines authorized (not paid) earlier do not join the order.
func TestRepeatRunFreshCart(t *testing.T) {
	d := deploy(t, 15000)
	for i := 0; i < 2; i++ {
		if _, err := d.supervised(t, "sup-repeat", supervisor.Settings{AutoApproveCents: 20000}, ""); err != nil {
			t.Fatal(err)
		}
	}
	if n := strings.Count(d.trace.String(), "ALLOW $54.95 for order"); n != 2 {
		t.Fatalf("%d runs authorized $54.95, want 2\n%s", n, d.trace.String())
	}
}
