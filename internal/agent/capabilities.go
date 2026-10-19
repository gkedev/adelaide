package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"

	aauth "github.com/aauth-dev/aauth-go"
)

// capabilityRT declares the agent's capabilities (draft -11 §11.7) on its
// person and auth token requests, then re-signs them.
//
// aauth-go v0.2's Transport builds those requests itself and offers no way
// to set TokenRequestHints.Capabilities, and a PS that must reach the person
// (Hellō) answers user_unreachable without "interaction". Until the library
// exposes it, this wrapper adds the member to JSON token requests bound for
// the person server and signs the request again with the agent's key.
type capabilityRT struct {
	ps           string // the person server origin
	capabilities []string
	agent        *aauth.Agent
	base         http.RoundTripper
}

// RoundTrip adds capabilities, then (with CHIPIN_DEBUG_PS=1) logs the
// person server's responses with tokens redacted.
func (c capabilityRT) RoundTrip(r *http.Request) (*http.Response, error) {
	res, err := c.roundTrip(r)
	// A poll answered 202 without Location: per the draft -11 §11.8.4 state
	// machine the agent keeps polling the pending URL it already has. Hellō
	// omits Location on poll responses, and aauth-go v0.2 requires it on
	// every 202, so supply the URL being polled (same origin by definition).
	if err == nil && r.Method == http.MethodGet && res.StatusCode == http.StatusAccepted &&
		res.Header.Get("Location") == "" && strings.HasPrefix(r.URL.String(), c.ps) {
		res.Header.Set("Location", r.URL.String())
	}
	if err == nil && os.Getenv("CHIPIN_DEBUG_PS") == "1" && strings.HasPrefix(r.URL.String(), c.ps) {
		body, _ := io.ReadAll(res.Body)
		res.Body = io.NopCloser(bytes.NewReader(body))
		var hs []string
		for k, v := range res.Header {
			switch strings.ToLower(k) {
			case "set-cookie", "signature", "signature-input":
				continue
			}
			hs = append(hs, k+": "+redact(strings.Join(v, ", ")))
		}
		fmt.Fprintf(os.Stderr, "[ps] %s %s -> %d\n  %s\n  body: %s\n", r.Method, r.URL.Path, res.StatusCode, strings.Join(hs, "\n  "), redact(string(body)))
	}
	return res, err
}

var jwtLike = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`)

func redact(s string) string { return jwtLike.ReplaceAllString(s, "<jwt>") }

func (c capabilityRT) roundTrip(r *http.Request) (*http.Response, error) {
	base := c.base
	if base == nil {
		base = http.DefaultTransport
	}
	if r.Method != http.MethodPost || r.Body == nil || !strings.HasPrefix(r.URL.String(), c.ps) ||
		!strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		return base.RoundTrip(r)
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if json.Unmarshal(body, &m) != nil || (m["resource"] == nil && m["resource_token"] == nil) || m["capabilities"] != nil {
		r.Body = io.NopCloser(bytes.NewReader(body))
		return base.RoundTrip(r)
	}
	m["capabilities"] = c.capabilities
	if body, err = json.Marshal(m); err != nil {
		return nil, err
	}
	r = r.Clone(r.Context())
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	r.Header.Del(aauth.HeaderSignature)
	r.Header.Del(aauth.HeaderSignatureInput)
	r.Header.Del("Content-Digest")
	if err := aauth.SignRequest(r, c.agent.Key, ""); err != nil {
		return nil, err
	}
	return base.RoundTrip(r)
}
