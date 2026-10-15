package agent

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
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

func (c capabilityRT) RoundTrip(r *http.Request) (*http.Response, error) {
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
