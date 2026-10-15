// Package spend holds the two money rules every party in the ChipIn demo
// agrees on: how a checkout amount travels in an AAuth scope, and how a
// mission states its budget.
//
// The amount rides in the resource token's scope (draft -11 §11.10), so the
// person server (the person's budget) and the access server (the shop's
// policy) both see exactly what the agent is asking to spend, and the auth
// token the shop later verifies names that same amount.
package spend

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ScopeCheckout is the scope a payment requires.
const ScopeCheckout = "checkout:pay"

// Currency is the only currency the demo charges in.
const Currency = "usd"

// CheckoutScope is the scope for paying cents in Currency:
// "checkout:pay amount:usd:5990".
func CheckoutScope(cents int64) string {
	return fmt.Sprintf("%s amount:%s:%d", ScopeCheckout, Currency, cents)
}

// OrderScope is the scope for one specific purchase: the amount and the
// SHA-256 of the merchant's canonical order (its offer). The auth token
// that grants it is the approval of exactly that order.
func OrderScope(cents int64, orderHash string) string {
	return CheckoutScope(cents) + " order:" + orderHash
}

// OrderFromScope returns the order hash a scope names, or "".
func OrderFromScope(scope string) string {
	for _, s := range strings.Fields(scope) {
		if h, ok := strings.CutPrefix(s, "order:"); ok {
			return h
		}
	}
	return ""
}

// AmountFromScope returns the amount a checkout scope authorizes, and false
// when scope does not authorize a checkout.
func AmountFromScope(scope string) (int64, bool) {
	var checkout bool
	amount := int64(-1)
	for _, s := range strings.Fields(scope) {
		if s == ScopeCheckout {
			checkout = true
			continue
		}
		rest, ok := strings.CutPrefix(s, "amount:"+Currency+":")
		if !ok {
			continue
		}
		n, err := strconv.ParseInt(rest, 10, 64)
		if err != nil || n < 0 {
			return 0, false
		}
		amount = n
	}
	return amount, checkout && amount >= 0
}

var budgetLine = regexp.MustCompile(`(?mi)^\s*budget:\s*\$?\s*([0-9]+(?:\.[0-9]{1,2})?)\s*usd\s*$`)

// BudgetLine is the line a mission description carries its budget in.
func BudgetLine(cents int64) string {
	return "Budget: " + Dollars(cents) + " USD"
}

// BudgetFromDescription finds the "Budget: $60.00 USD" line of a mission
// description, and false when it has none.
func BudgetFromDescription(desc string) (int64, bool) {
	m := budgetLine.FindStringSubmatch(desc)
	if m == nil {
		return 0, false
	}
	whole, frac, _ := strings.Cut(m[1], ".")
	for len(frac) < 2 {
		frac += "0"
	}
	n, err := strconv.ParseInt(whole+frac, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// Dollars formats cents as "$59.90".
func Dollars(cents int64) string {
	sign := ""
	if cents < 0 {
		sign, cents = "-", -cents
	}
	return fmt.Sprintf("%s$%d.%02d", sign, cents/100, cents%100)
}
