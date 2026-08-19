package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// CodeSender delivers a verification code to a phone number.
//
// The interface is intentionally tiny so that swapping aggregators — or
// replacing the whole flow with Identity Platform's phone auth — touches one
// constructor and nothing else.
type CodeSender interface {
	Send(ctx context.Context, phone, code string, ttl time.Duration) error
	Name() string
}

// NewCodeSender builds the configured sender.
func NewCodeSender(cfg SMSConfig, log *slog.Logger) (CodeSender, error) {
	switch cfg.Provider {
	case "log":
		return &logSender{log: log}, nil
	case "noop":
		return &noopSender{}, nil
	case "webhook":
		return &webhookSender{
			url:        cfg.WebhookURL,
			authHeader: cfg.WebhookAuthHeader,
			client: &http.Client{
				Timeout: orDefaultDuration(cfg.Timeout, 5*time.Second),
			},
		}, nil
	}
	return nil, fmt.Errorf("auth: unknown SMS provider %q (want log|noop|webhook)", cfg.Provider)
}

// logSender prints the code. Development only — LoadConfig refuses to start
// with this provider when ENV=prod.
type logSender struct{ log *slog.Logger }

func (s *logSender) Name() string { return "log" }

func (s *logSender) Send(_ context.Context, phone, code string, ttl time.Duration) error {
	s.log.Warn("verification code (development sender)",
		"phone", phone, "code", code, "ttl", ttl.String())
	return nil
}

// noopSender drops codes on the floor, for load tests that only exercise the
// paths after verification.
type noopSender struct{}

func (*noopSender) Name() string { return "noop" }

func (*noopSender) Send(context.Context, string, string, time.Duration) error { return nil }

// webhookSender POSTs the code to an operator-supplied endpoint.
//
// Every SMS aggregator worth using is reachable this way, either directly or
// through a two-line Cloud Function that adapts our payload to theirs. Keeping
// provider SDKs out of this binary means no vendor library in the auth
// service's dependency tree — which is the one binary where a supply-chain
// compromise would be worst.
type webhookSender struct {
	url        string
	authHeader string
	client     *http.Client
}

func (*webhookSender) Name() string { return "webhook" }

type webhookPayload struct {
	Phone      string `json:"phone"`
	Code       string `json:"code"`
	TTLSeconds int    `json:"ttl_seconds"`
}

func (s *webhookSender) Send(ctx context.Context, phone, code string, ttl time.Duration) error {
	body, err := json.Marshal(webhookPayload{
		Phone: phone, Code: code, TTLSeconds: int(ttl.Seconds()),
	})
	if err != nil {
		return fmt.Errorf("auth: marshal webhook payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("auth: build webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if s.authHeader != "" {
		req.Header.Set("Authorization", s.authHeader)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("auth: sms webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		// Read a bounded amount of the body for the error message: some
		// aggregators return useful detail, and none of them need more than
		// a few hundred bytes to say what went wrong.
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("auth: sms webhook returned %s: %s", resp.Status, bytes.TrimSpace(detail))
	}
	return nil
}

func orDefaultDuration(v, def time.Duration) time.Duration {
	if v == 0 {
		return def
	}
	return v
}
