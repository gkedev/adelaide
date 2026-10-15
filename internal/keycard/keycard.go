// Package keycard makes Keycard (https://keycard.ai) the enforcer of each
// player's shopping mission. When a player approves a selection, ChipIn
// publishes the player's choices (brands, pack sizes, max cost) as a Cedar
// policy in the Keycard zone; before any purchase is authorized, ChipIn's
// access server asks Keycard to evaluate that policy for every order line.
//
// Cedar compares strings in context.scopes, so each line is described as
// scopes: chipin:selection:<id>, brand:<brand>, pack:<pack>, and
// spend:within:usd:<M> for every $5 step M at or above the mission's total
// spending after this order. "Spending ≤ max" is then a set membership.
package keycard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

// SchemaVersion is the Keycard Cedar schema the policies are written against.
const SchemaVersion = "2026-06-18"

// SpendStepCents is the granularity of spending limits ($5), and
// SpendCeilingCents the largest limit expressed ($1,000).
const (
	SpendStepCents    = 500
	SpendCeilingCents = 100000
)

// Client talks to the Keycard management API with a service account.
type Client struct {
	ZoneID, ClientID, ClientSecret string
	// BaseURL defaults to https://api.keycard.ai.
	BaseURL    string
	HTTPClient *http.Client
	// Origin is ChipIn's origin; it identifies ChipIn's Keycard entities.
	Origin string

	mu         sync.Mutex
	token      string
	tokenExp   time.Time
	appID      string
	resourceID string
}

// Mission is what a policy is generated from.
type Mission struct {
	ID           string
	Summary      string
	Brands       []string // "Penn", "Wilson", …
	Packs        []string // "4", "8", "12", "18", "24" (cans)
	MaxCostCents int64
}

// Line is one order line to check.
type Line struct {
	Brand string
	Pack  string // "4", "8", "12", "18", "24", or "" when not one of them
}

// Policy is a published mission policy.
type Policy struct {
	ID, VersionID, Name string
}

// Cedar is the policy for m.
func Cedar(m Mission) string {
	or := func(prefix string, vals []string) string {
		parts := make([]string, len(vals))
		for i, v := range vals {
			parts[i] = fmt.Sprintf("context.scopes.contains(%q)", prefix+strings.ToLower(v))
		}
		return "(" + strings.Join(parts, " || ") + ")"
	}
	max := (m.MaxCostCents / SpendStepCents) * SpendStepCents
	return fmt.Sprintf(`// ChipIn shopping mission %s
// %s
@id("chipin-mission")
permit (principal, action, resource)
when {
  context has scopes &&
  context.scopes.contains(%q) &&
  %s &&
  %s &&
  context.scopes.contains("spend:within:usd:%d")
};
`, m.ID, m.Summary, "chipin:selection:"+m.ID, or("brand:", m.Brands), or("pack:", m.Packs), max)
}

// Scopes describes one order line for evaluation; totalCents is the
// mission's spending including this order.
func Scopes(missionID string, l Line, totalCents int64) []string {
	s := []string{"chipin:selection:" + missionID, "brand:" + strings.ToLower(l.Brand)}
	if l.Pack != "" {
		s = append(s, "pack:"+l.Pack)
	}
	first := ((totalCents + SpendStepCents - 1) / SpendStepCents) * SpendStepCents
	for m := first; m <= SpendCeilingCents; m += SpendStepCents {
		s = append(s, fmt.Sprintf("spend:within:usd:%d", m))
	}
	return s
}

// Publish creates the mission's policy in the zone.
func (c *Client) Publish(ctx context.Context, m Mission) (*Policy, error) {
	short := m.ID
	if len(short) > 10 {
		short = short[:10]
	}
	name := "chipin-mission-" + strings.ToLower(strings.NewReplacer("_", "-").Replace(short))
	var pol struct {
		ID string `json:"id"`
	}
	if err := c.do(ctx, http.MethodPost, "policies", map[string]any{"name": name, "description": "ChipIn mission: " + m.Summary}, &pol); err != nil {
		return nil, fmt.Errorf("keycard: create policy: %w", err)
	}
	var ver struct {
		ID string `json:"id"`
	}
	if err := c.do(ctx, http.MethodPost, "policies/"+pol.ID+"/versions", map[string]any{"cedar_raw": Cedar(m), "schema_version": SchemaVersion}, &ver); err != nil {
		return nil, fmt.Errorf("keycard: create policy version: %w", err)
	}
	return &Policy{ID: pol.ID, VersionID: ver.ID, Name: name}, nil
}

// Decision is Keycard's answer for one line.
type Decision struct {
	Allow       bool
	Determining []string
}

// Evaluate asks Keycard to evaluate policy p for scopes.
func (c *Client) Evaluate(ctx context.Context, p *Policy, scopes []string) (*Decision, error) {
	app, res, err := c.entities(ctx)
	if err != nil {
		return nil, err
	}
	var out struct {
		Decision    string   `json:"decision"`
		Determining []string `json:"determining_policies"`
	}
	body := map[string]any{
		"principal_type": "application", "principal_id": app, "action": "any", "resource_id": res,
		"policy_source": map[string]any{"policy": map[string]any{"policy_id": p.ID}},
		"context":       map[string]any{"scopes": scopes},
	}
	if err := c.do(ctx, http.MethodPost, "policy-evaluations", body, &out); err != nil {
		return nil, fmt.Errorf("keycard: evaluate: %w", err)
	}
	return &Decision{Allow: out.Decision == "allow", Determining: out.Determining}, nil
}

// entities finds or creates ChipIn's application and resource in the zone
// (the principal and resource evaluations are made for).
func (c *Client) entities(ctx context.Context) (string, string, error) {
	c.mu.Lock()
	app, res := c.appID, c.resourceID
	c.mu.Unlock()
	if app != "" && res != "" {
		return app, res, nil
	}
	appIdent, resIdent := strings.TrimSuffix(c.Origin, "/")+"/agent", strings.TrimSuffix(c.Origin, "/")
	app, err := c.find(ctx, "applications", appIdent)
	if err != nil {
		return "", "", err
	}
	if app == "" {
		var a struct {
			ID string `json:"id"`
		}
		if err := c.do(ctx, http.MethodPost, "applications", map[string]any{"name": "ChipIn shopping agent", "identifier": appIdent,
			"description": "AAuth shopping agent; ChipIn missions are evaluated for it"}, &a); err != nil {
			return "", "", fmt.Errorf("keycard: create application: %w", err)
		}
		app = a.ID
	}
	res, err = c.find(ctx, "resources", resIdent)
	if err != nil {
		return "", "", err
	}
	if res == "" {
		var r struct {
			ID string `json:"id"`
		}
		if err := c.do(ctx, http.MethodPost, "resources", map[string]any{"name": "ChipIn", "identifier": resIdent, "application_id": app,
			"description": "ChipIn shop (AAuth resource, MCP)"}, &r); err != nil {
			return "", "", fmt.Errorf("keycard: create resource: %w", err)
		}
		res = r.ID
	}
	c.mu.Lock()
	c.appID, c.resourceID = app, res
	c.mu.Unlock()
	return app, res, nil
}

func (c *Client) find(ctx context.Context, kind, identifier string) (string, error) {
	var list struct {
		Items []struct {
			ID         string `json:"id"`
			Identifier string `json:"identifier"`
		} `json:"items"`
	}
	if err := c.do(ctx, http.MethodGet, kind+"?identifier="+url.QueryEscape(identifier), nil, &list); err != nil {
		return "", fmt.Errorf("keycard: list %s: %w", kind, err)
	}
	i := slices.IndexFunc(list.Items, func(x struct {
		ID         string `json:"id"`
		Identifier string `json:"identifier"`
	}) bool {
		return x.Identifier == identifier
	})
	if i < 0 {
		return "", nil
	}
	return list.Items[i].ID, nil
}

func (c *Client) base() string {
	if c.BaseURL != "" {
		return strings.TrimSuffix(c.BaseURL, "/")
	}
	return "https://api.keycard.ai"
}

func (c *Client) hc() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: 20 * time.Second}
}

func (c *Client) bearer(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Now().Before(c.tokenExp) {
		return c.token, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base()+"/service-account-token", strings.NewReader("grant_type=client_credentials"))
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(c.ClientID, c.ClientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "chipin/1")
	res, err := c.hc().Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	var t struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if res.StatusCode != http.StatusOK || json.NewDecoder(res.Body).Decode(&t) != nil || t.AccessToken == "" {
		return "", fmt.Errorf("keycard: service account token: HTTP %d", res.StatusCode)
	}
	c.token, c.tokenExp = t.AccessToken, time.Now().Add(time.Duration(max(t.ExpiresIn-60, 30))*time.Second)
	return c.token, nil
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	if c.ZoneID == "" || c.ClientID == "" || c.ClientSecret == "" {
		return errors.New("keycard: zone and service account are required")
	}
	tok, err := c.bearer(ctx)
	if err != nil {
		return err
	}
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base()+"/zones/"+c.ZoneID+"/"+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "chipin/1")
	res, err := c.hc().Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode/100 != 2 {
		var e struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(b, &e)
		return fmt.Errorf("HTTP %d: %s", res.StatusCode, e.Message)
	}
	if out == nil || len(b) == 0 {
		return nil
	}
	return json.Unmarshal(b, out)
}
