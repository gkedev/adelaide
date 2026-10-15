package spend

import "testing"

func TestCheckoutScopeRoundTrip(t *testing.T) {
	s := CheckoutScope(5990)
	if s != "checkout:pay amount:usd:5990" {
		t.Fatalf("scope %q", s)
	}
	if n, ok := AmountFromScope(s); !ok || n != 5990 {
		t.Fatalf("amount %d %v", n, ok)
	}
	for _, bad := range []string{"", "checkout:pay", "amount:usd:10", "checkout:pay amount:usd:-1", "checkout:pay amount:eur:10"} {
		if _, ok := AmountFromScope(bad); ok {
			t.Errorf("%q authorized a checkout", bad)
		}
	}
}

func TestBudget(t *testing.T) {
	desc := "# Balls for Monday\n\n" + BudgetLine(6000) + "\n"
	if n, ok := BudgetFromDescription(desc); !ok || n != 6000 {
		t.Fatalf("budget %d %v", n, ok)
	}
	if n, ok := BudgetFromDescription("budget: 7.5 usd"); !ok || n != 750 {
		t.Fatalf("budget %d %v", n, ok)
	}
	if _, ok := BudgetFromDescription("no money here"); ok {
		t.Fatal("found a budget")
	}
	if Dollars(5990) != "$59.90" || Dollars(5) != "$0.05" {
		t.Fatal(Dollars(5990), Dollars(5))
	}
}
