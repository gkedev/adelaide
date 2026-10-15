package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
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
	} {
		rec := httptest.NewRecorder()
		h.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != want {
			t.Errorf("GET %s: %d, want %d", path, rec.Code, want)
		}
	}
}
