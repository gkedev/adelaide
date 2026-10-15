// Package payments is ChipIn's Stripe integration: Shared Payment Tokens
// (SPTs) for agent-initiated payments, with a plain test-card PaymentIntent
// as the fallback when an account has no SPT access.
//
// It talks to the Stripe REST API directly (form-encoded, no SDK) and
// refuses live keys: the demo is sandbox-only.
package payments

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// APIVersion is the Stripe API version SPTs are available under (preview).
const APIVersion = "2026-09-30.preview"

// Stripe is a sandbox Stripe client.
type Stripe struct {
	// Key is a sandbox secret or restricted key (sk_test_ or rk_test_).
	Key string
	// BaseURL defaults to https://api.stripe.com.
	BaseURL string
	// HTTPClient defaults to a client with a 30 second timeout.
	HTTPClient *http.Client
}

// New returns a client for key, refusing anything but a sandbox key.
func New(key string) (*Stripe, error) {
	key = strings.TrimSpace(key)
	if !strings.HasPrefix(key, "sk_test_") && !strings.HasPrefix(key, "rk_test_") {
		return nil, errors.New("payments: only Stripe sandbox keys (sk_test_ or rk_test_) are accepted")
	}
	return &Stripe{Key: key}, nil
}

// Error is a Stripe API error.
type Error struct {
	Status  int
	Type    string `json:"type"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("stripe: %d %s %s: %s", e.Status, e.Type, e.Code, e.Message)
}

// SPT is a granted Shared Payment Token.
type SPT struct {
	ID          string `json:"id"`
	UsageLimits struct {
		Currency  string `json:"currency"`
		MaxAmount int64  `json:"max_amount"`
		ExpiresAt int64  `json:"expires_at"`
	} `json:"usage_limits"`
}

// GrantTestSPT stands in for an agent wallet: it creates a granted SPT for
// Stripe's test card with the given cap and lifetime, through Stripe's
// sandbox test helper. A production agent issues the token from its own
// Stripe account (shared_payment/issued_tokens) instead.
func (s *Stripe) GrantTestSPT(ctx context.Context, maxCents int64, ttl time.Duration) (*SPT, error) {
	form := url.Values{
		"payment_method":           {"pm_card_visa"},
		"usage_limits[currency]":   {"usd"},
		"usage_limits[max_amount]": {strconv.FormatInt(maxCents, 10)},
		"usage_limits[expires_at]": {strconv.FormatInt(time.Now().Add(ttl).Unix(), 10)},
	}
	var spt SPT
	if err := s.post(ctx, "/v1/test_helpers/shared_payment/granted_tokens", form, "", &spt); err != nil {
		return nil, err
	}
	return &spt, nil
}

// Charge describes one payment.
type Charge struct {
	AmountCents int64
	Description string
	// SPT pays with a shared payment token; empty pays with Stripe's test
	// Visa (the fallback for accounts without SPT access).
	SPT string
	// Metadata is attached to the PaymentIntent (strings only).
	Metadata map[string]string
	// IdempotencyKey makes a retried charge safe.
	IdempotencyKey string
}

// PaymentIntent is the part of a PaymentIntent the demo reports.
type PaymentIntent struct {
	ID       string `json:"id"`
	Status   string `json:"status"`
	Amount   int64  `json:"amount"`
	Currency string `json:"currency"`
	Livemode bool   `json:"livemode"`
}

// DashboardURL links the payment in the Stripe sandbox dashboard.
func (p *PaymentIntent) DashboardURL() string {
	return "https://dashboard.stripe.com/test/payments/" + p.ID
}

// Pay creates and confirms a PaymentIntent in USD.
func (s *Stripe) Pay(ctx context.Context, c Charge) (*PaymentIntent, error) {
	if c.AmountCents <= 0 {
		return nil, errors.New("payments: amount must be positive")
	}
	form := url.Values{
		"amount":      {strconv.FormatInt(c.AmountCents, 10)},
		"currency":    {"usd"},
		"confirm":     {"true"},
		"description": {c.Description},
	}
	if c.SPT != "" {
		form.Set("payment_method_data[shared_payment_granted_token]", c.SPT)
	} else {
		form.Set("payment_method", "pm_card_visa")
		form.Set("payment_method_types[]", "card")
	}
	for k, v := range c.Metadata {
		form.Set("metadata["+k+"]", v)
	}
	var pi PaymentIntent
	if err := s.post(ctx, "/v1/payment_intents", form, c.IdempotencyKey, &pi); err != nil {
		return nil, err
	}
	if pi.Livemode {
		return nil, errors.New("payments: Stripe reported a live-mode payment; refusing")
	}
	return &pi, nil
}

func (s *Stripe) post(ctx context.Context, path string, form url.Values, idem string, out any) error {
	base := s.BaseURL
	if base == "" {
		base = "https://api.stripe.com"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(base, "/")+path, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.SetBasicAuth(s.Key, "")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Stripe-Version", APIVersion)
	if idem != "" {
		req.Header.Set("Idempotency-Key", idem)
	}
	hc := s.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	res, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return err
	}
	if res.StatusCode/100 != 2 {
		var e struct {
			Error Error `json:"error"`
		}
		_ = json.Unmarshal(body, &e)
		e.Error.Status = res.StatusCode
		return &e.Error
	}
	return json.Unmarshal(body, out)
}
