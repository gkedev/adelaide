// Package localps is a local person server built on aauth-go, standing in
// for Hellō (https://person.hello.coop) in tests and offline runs. Like
// Hellō it has no missions; it binds the agent to one person and approves
// each request automatically, where Hellō asks the person.
package localps

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"

	aauth "github.com/aauth-dev/aauth-go"
	"github.com/aauth-dev/aauth-go/accessserver"
	"github.com/aauth-dev/aauth-go/personserver"

	"github.com/gkedev/adelaide/internal/spend"
)

// New returns a person server for issuer that approves as person.
func New(issuer, person string, hc *http.Client, log func(role, msg string)) (*personserver.Server, error) {
	if log == nil {
		log = func(string, string) {}
	}
	key, err := aauth.GenerateKey(aauth.AlgEd25519)
	if err != nil {
		return nil, err
	}
	subjectKey := make([]byte, 32)
	if _, err := rand.Read(subjectKey); err != nil {
		return nil, err
	}
	var ps *personserver.Server
	fed := federator{}
	ps, err = personserver.New(personserver.Config{
		HTTPClient: hc, Issuer: issuer, Key: key, SubjectKey: subjectKey,
		Store: personserver.NewMemoryStore(),
		Decider: personserver.DeciderFunc(func(_ context.Context, r *personserver.TokenRequest) (personserver.Decision, error) {
			g := personserver.Grant{}
			if r.Person == "" {
				g.Person = person
				log("Person", fmt.Sprintf("%s signs in and links agent %s", person, r.Agent.Subject))
			}
			if amount, ok := spend.AmountFromScope(r.Scope); ok {
				log("Person", fmt.Sprintf("%s approves order %s for %s", person, short(spend.OrderFromScope(r.Scope)), spend.Dollars(amount)))
			}
			return personserver.Allow(g), nil
		}),
		Federator:                   &fed,
		InsecureSkipIdentifierCheck: true,
	})
	if err != nil {
		return nil, err
	}
	fed.f = accessserver.NewClient(ps.Signer(), hc)
	return ps, nil
}

type federator struct{ f personserver.Federator }

func (l *federator) Federate(ctx context.Context, r *personserver.FederationRequest) (*personserver.FederationResponse, error) {
	return l.f.Federate(ctx, r)
}
func (l *federator) Poll(ctx context.Context, u string) (*personserver.FederationResponse, error) {
	return l.f.Poll(ctx, u)
}
func (l *federator) Answer(ctx context.Context, u string, body any) error {
	return l.f.Answer(ctx, u, body)
}

func short(h string) string {
	if len(h) > 10 {
		return h[:10] + "…"
	}
	return h
}
