package authn

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/pervagans/messaging-app/pkg/config"
)

// RefreshingVerifier keeps a Verifier current against a JWKS endpoint.
//
// Signing keys rotate. If every service pinned the key it loaded at startup, a
// rotation would mean a synchronised redeploy of the whole fleet, and any
// service that missed it would start rejecting valid tokens. Refreshing in the
// background means a rotation is a change in exactly one service.
//
// The stored verifier is swapped atomically, so a refresh never makes
// verification block, and a failed refresh leaves the previous keys in place —
// the auth service being briefly unreachable must not stop token validation.
type RefreshingVerifier struct {
	v atomic.Pointer[Verifier]

	url      string
	issuer   string
	audience string
	client   *http.Client
	log      *slog.Logger
}

// LoadVerifier builds a verifier from the environment.
//
// In development the signing key itself may be supplied through
// JWT_SIGNING_KEY_PEM so the stack runs without service discovery. In every
// other environment the key set is fetched from JWKS_URL.
func LoadVerifier(ctx context.Context, log *slog.Logger) (*RefreshingVerifier, error) {
	issuer := config.String("JWT_ISSUER", "messaging")
	audience := config.String("JWT_AUDIENCE", "messaging-api")

	if pem := config.Secret("JWT_SIGNING_KEY_PEM", ""); pem != "" {
		iss, err := NewIssuer(IssuerConfig{
			PrivateKeyPEM: pem,
			KeyID:         config.String("JWT_SIGNING_KEY_ID", "dev"),
			Issuer:        issuer,
			Audience:      audience,
		})
		if err != nil {
			return nil, err
		}
		v, err := NewVerifierFromIssuer(iss)
		if err != nil {
			return nil, err
		}
		rv := &RefreshingVerifier{issuer: issuer, audience: audience, log: log}
		rv.v.Store(v)
		return rv, nil
	}

	rv := &RefreshingVerifier{
		url: config.String("JWKS_URL",
			"http://auth-service.messaging.svc.cluster.local/.well-known/jwks.json"),
		issuer:   issuer,
		audience: audience,
		client:   &http.Client{Timeout: 10 * time.Second},
		log:      log,
	}
	if err := rv.refresh(ctx); err != nil {
		return nil, err
	}
	return rv, nil
}

// Current returns the verifier in force right now.
func (r *RefreshingVerifier) Current() *Verifier { return r.v.Load() }

// Verify delegates to the current verifier.
func (r *RefreshingVerifier) Verify(raw string, want TokenType) (*Claims, error) {
	return r.v.Load().Verify(raw, want)
}

// Run refreshes the key set on an interval until ctx is cancelled.
func (r *RefreshingVerifier) Run(ctx context.Context, every time.Duration) {
	if r.url == "" {
		return // statically configured; nothing to refresh
	}
	if every <= 0 {
		every = 15 * time.Minute
	}
	t := time.NewTicker(every)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := r.refresh(ctx); err != nil {
				// Keep the previous keys: a stale key set that still verifies
				// live tokens beats no key set at all.
				r.log.Warn("JWKS refresh failed, keeping the previous key set", "error", err)
			}
		}
	}
}

func (r *RefreshingVerifier) refresh(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.url, nil)
	if err != nil {
		return fmt.Errorf("authn: build JWKS request: %w", err)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("authn: fetch JWKS from %s: %w", r.url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("authn: JWKS endpoint returned %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("authn: read JWKS: %w", err)
	}

	v, err := NewVerifier(body, r.issuer, r.audience)
	if err != nil {
		return err
	}
	r.v.Store(v)
	return nil
}
