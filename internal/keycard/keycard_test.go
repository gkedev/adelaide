package keycard

import (
	"slices"
	"strings"
	"testing"
)

func TestCedarAndScopes(t *testing.T) {
	p := Cedar(Mission{ID: "abc", Summary: "Penn · up to $60.00", Brands: []string{"Penn", "Dunlop"}, Packs: []string{"can", "24"}, MaxCostCents: 6099})
	for _, want := range []string{`"chipin:selection:abc"`, `context.scopes.contains("brand:penn") || context.scopes.contains("brand:dunlop")`,
		`context.scopes.contains("pack:can") || context.scopes.contains("pack:24")`, `"spend:within:usd:6000"`} {
		if !strings.Contains(p, want) {
			t.Errorf("policy lacks %s:\n%s", want, p)
		}
	}
	under := Scopes("abc", Line{Brand: "Penn", Pack: "can"}, 3192)
	if !slices.Contains(under, "spend:within:usd:6000") || !slices.Contains(under, "spend:within:usd:3500") || slices.Contains(under, "spend:within:usd:3000") {
		t.Fatalf("spend scopes for $31.92: %v", under[:6])
	}
	if over := Scopes("abc", Line{Brand: "Penn", Pack: "24"}, 8995); slices.Contains(over, "spend:within:usd:6000") {
		t.Fatal("$89.95 is within a $60 limit")
	}
}
