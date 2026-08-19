package kafkax

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/segmentio/kafka-go/sasl"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// kafkaOAuthScope is the scope Google Cloud Managed Service for Apache Kafka
// checks. Broker-side authorisation is then done with IAM roles
// (roles/managedkafka.client plus topic-level bindings), not with ACLs.
const kafkaOAuthScope = "https://www.googleapis.com/auth/cloud-platform"

// googleOAuthBearer implements SASL/OAUTHBEARER (RFC 7628) using Application
// Default Credentials.
//
// On GKE with Workload Identity the credentials come from the metadata
// server, scoped to the Google service account bound to the pod's Kubernetes
// service account. No key material ever touches the container filesystem.
//
// The oauth2 token source caches and refreshes the token itself, so Start
// being called per connection is cheap.
type googleOAuthBearer struct {
	once sync.Once
	err  error
	ts   oauth2.TokenSource
}

var _ sasl.Mechanism = (*googleOAuthBearer)(nil)

func newGoogleOAuthMechanism(ctx context.Context) (sasl.Mechanism, error) {
	m := &googleOAuthBearer{}
	// Resolve eagerly so a misconfigured Workload Identity binding fails at
	// startup with a clear message instead of on the first publish.
	if _, err := m.tokenSource(ctx); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *googleOAuthBearer) tokenSource(ctx context.Context) (oauth2.TokenSource, error) {
	m.once.Do(func() {
		ts, err := google.DefaultTokenSource(ctx, kafkaOAuthScope)
		if err != nil {
			m.err = fmt.Errorf("kafkax: google default credentials: %w", err)
			return
		}
		m.ts = ts
	})
	return m.ts, m.err
}

func (m *googleOAuthBearer) Name() string { return "OAUTHBEARER" }

func (m *googleOAuthBearer) Start(ctx context.Context) (sasl.StateMachine, []byte, error) {
	ts, err := m.tokenSource(ctx)
	if err != nil {
		return nil, nil, err
	}
	tok, err := ts.Token()
	if err != nil {
		return nil, nil, fmt.Errorf("kafkax: fetch access token: %w", err)
	}

	// RFC 7628 client-first message:
	//   gs2-header , %x01 , "auth=Bearer " token , %x01 , %x01
	// The gs2 header is "n,," — no channel binding, no authzid.
	var b strings.Builder
	b.WriteString("n,,\x01auth=Bearer ")
	b.WriteString(tok.AccessToken)
	b.WriteString("\x01\x01")

	return &oauthBearerSession{}, []byte(b.String()), nil
}

type oauthBearerSession struct{ steps int }

func (s *oauthBearerSession) Next(_ context.Context, challenge []byte) (bool, []byte, error) {
	s.steps++
	// A successful OAUTHBEARER exchange is one round trip: the broker replies
	// with an empty server-final message. Any payload here is the JSON error
	// document described in RFC 7628 §3.2.2.
	if len(challenge) == 0 {
		return true, nil, nil
	}
	if s.steps > 2 {
		return false, nil, fmt.Errorf("kafkax: OAUTHBEARER did not converge")
	}
	return false, nil, fmt.Errorf("kafkax: broker rejected OAUTHBEARER token: %s", strings.TrimSpace(string(challenge)))
}
