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

// supervised runs the agent under ChipIn's PS and its Supervisor.
func (d *deployment) supervised(t *testing.T, name string, st supervisor.Settings, behaviour string) (*agent.Result, error) {
	d.sup.Start(name, "player-1", st)
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

func TestSupervisorApproves(t *testing.T) {
	d := deploy(t, 15000)
	res, err := d.supervised(t, "sup-approve", supervisor.Settings{AutoApproveCents: 10000}, "")
	if err != nil {
		t.Fatal(err)
	}
	v := d.sup.View("sup-approve")
	if !res.Authorized || v.MissionID == "" || !strings.Contains(verdicts(v), "Mission:approve") || !strings.HasSuffix(verdicts(v), "Purchase:approve") {
		t.Fatalf("authorized %v log %s", res.Authorized, verdicts(v))
	}
	if !strings.Contains(d.trace.String(), "ALLOW $54.95 for order") {
		t.Error("ChipIn AS did not see the purchase")
	}
}

func TestSupervisorSteers(t *testing.T) {
	d := deploy(t, 15000)
	res, err := d.supervised(t, "sup-steer", supervisor.Settings{AutoApproveCents: 20000}, "overbuy")
	if err != nil {
		t.Fatal(err)
	}
	v := d.sup.View("sup-steer")
	if !res.Authorized || res.Picked.Quantity != 1 || !strings.Contains(verdicts(v), "Purchase:steer Purchase:approve") {
		t.Fatalf("picked %+v log %s", res.Picked, verdicts(v))
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
	if !res.Authorized || len(res.Denials) != 1 || !strings.HasSuffix(verdicts(v), "Purchase:approve Purchase:deny") {
		t.Fatalf("denials %q log %s", res.Denials, verdicts(v))
	}
}

func TestSupervisorEscalates(t *testing.T) {
	d := deploy(t, 15000)
	go func() {
		for i := 0; i < 200; i++ {
			time.Sleep(50 * time.Millisecond)
			if v := d.sup.View("sup-escalate"); v != nil && v.Escalation != nil {
				if err := d.sup.Decide(context.Background(), "sup-escalate", true); err != nil {
					t.Error(err)
				}
				return
			}
		}
	}()
	res, err := d.supervised(t, "sup-escalate", supervisor.Settings{AutoApproveCents: 3000}, "")
	if err != nil {
		t.Fatal(err)
	}
	v := d.sup.View("sup-escalate")
	if !res.Authorized || !strings.HasSuffix(verdicts(v), "Purchase:escalate Purchase:approve") || v.Log[len(v.Log)-1].By != "You" {
		t.Fatalf("log %s", verdicts(v))
	}
}

// TestHostedSupervisorFlow: the /supervisor/ page's API with "you decide
// everything": the mission and the purchase each wait on the player.
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
	call("POST", "/api/sup/recommend", `{"brands":["Penn"],"case":"12","max_cost":60,"supervisor":"person","auto_approve":0}`)
	waitFor("mission escalation", escalated)
	if job.Supervision.Escalation.Act != "Mission" || job.Supervision.Supervisor != "You" {
		t.Fatalf("escalation %+v", job.Supervision)
	}
	call("POST", "/api/sup/jobs/"+job.ID+"/decide", `{"approve":true}`)
	waitFor("shortlist", func() bool { return job.Status == "shortlist" })
	call("POST", "/api/sup/jobs/"+job.ID+"/choose", `{"choice":"1"}`)
	waitFor("purchase escalation", escalated)
	if job.Supervision.Escalation.Act != "Purchase" || !strings.Contains(job.Supervision.Escalation.Detail, "Buy 1 × Penn") {
		t.Fatalf("escalation %+v\n%s", job.Supervision.Escalation, d.trace.String())
	}
	call("POST", "/api/sup/jobs/"+job.ID+"/decide", `{"approve":true}`)
	waitFor("checkout", func() bool { return job.Status == "checkout" })
	if got := verdicts(job.Supervision); !strings.Contains(got, "Mission:escalate Mission:approve") || !strings.HasSuffix(got, "Purchase:escalate Purchase:approve") || job.Supervision.MissionID == "" {
		t.Fatalf("log %s", got)
	}
}
