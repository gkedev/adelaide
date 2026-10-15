package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	jwtv5 "github.com/golang-jwt/jwt/v5"
)

// TestHostRoutes builds the one-origin mux (route patterns must not
// conflict) and checks each role answers on its path.
func TestHostRoutes(t *testing.T) {
	o := options{public: t.TempDir(), enrollment: "x", dailyBudget: 60, maxOrder: 150}
	h, err := newHost(o, "https://chipin.example", "https://person.example", nil, nil, false, func(string, string) {})
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]int{
		"/.well-known/aauth-resource.json":    200,
		"/.well-known/aauth-agent.json":       200,
		"/.well-known/aauth-access.json":      200,
		"/.well-known/ucp/chip-in-agent.json": 200,
		"/jwks":                               200,
		"/healthz":                            200,
		"/robots.txt":                         200,
	} {
		rec := httptest.NewRecorder()
		h.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != want {
			t.Errorf("GET %s: %d, want %d", path, rec.Code, want)
		}
		if rec.Header().Get("X-Robots-Tag") != "noindex, nofollow" {
			t.Errorf("GET %s: no X-Robots-Tag", path)
		}
	}
}

// TestSingleAudienceIsAString: tokens ChipIn mints carry aud as a string
// (Hellō rejects a one-element array); init sets this for the process.
func TestSingleAudienceIsAString(t *testing.T) {
	b, _ := json.Marshal(jwtv5.RegisteredClaims{Audience: jwtv5.ClaimStrings{"https://as.example"}})
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if _, ok := m["aud"].(string); !ok {
		t.Fatalf("aud marshals as %T: %s", m["aud"], b)
	}
}
