// Package push sends notifications through Firebase Cloud Messaging.
//
// It speaks the FCM HTTP v1 API directly rather than through the Firebase
// Admin SDK. The SDK pulls in a large dependency tree to wrap what is, for our
// purposes, one POST with an OAuth token — and the token comes from Workload
// Identity either way, so there is nothing to configure and no key file.
package push

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const fcmScope = "https://www.googleapis.com/auth/firebase.messaging"

// Config configures the sender.
type Config struct {
	ProjectID string
	// DryRun asks FCM to validate without delivering. Used in dev and
	// staging so test traffic never wakes a real phone.
	DryRun  bool
	Timeout time.Duration
	// Concurrency bounds simultaneous sends. FCM v1 has no batch endpoint, so
	// a 200-member group means 200 requests; without a bound, one busy group
	// would open 200 sockets at once.
	Concurrency int
}

// Message is one notification for one device token.
type Message struct {
	Token    string
	Platform string // android|ios|web
	Title    string
	Body     string
	Data     map[string]string
	// CollapseKey lets FCM replace an undelivered notification with a newer
	// one. Keyed by chat, it means a phone that was off for an hour shows one
	// "3 new messages" rather than a wall of individual alerts.
	CollapseKey string
	Badge       int
	// TTL bounds how long FCM will try. A chat notification is worthless a day
	// later, so a short TTL avoids a burst of stale alerts when a device
	// comes back online.
	TTL time.Duration
}

// Result reports the outcome for one message.
type Result struct {
	OK bool
	// Unregistered means the token is permanently dead and must be deleted.
	Unregistered bool
	// Retryable means a transient FCM failure; the caller should retry.
	Retryable bool
	Error     string
}

// FCM is the sender.
type FCM struct {
	cfg    Config
	ts     oauth2.TokenSource
	client *http.Client
	log    *slog.Logger
	sem    chan struct{}
}

// NewFCM builds a sender using Application Default Credentials.
func NewFCM(ctx context.Context, cfg Config, log *slog.Logger) (*FCM, error) {
	if cfg.ProjectID == "" {
		return nil, errors.New("push: project id is required")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 32
	}

	ts, err := google.DefaultTokenSource(ctx, fcmScope)
	if err != nil {
		return nil, fmt.Errorf("push: google credentials: %w", err)
	}

	return &FCM{
		cfg: cfg,
		ts:  ts,
		client: &http.Client{
			Timeout: cfg.Timeout,
			Transport: &http.Transport{
				MaxIdleConns:        200,
				MaxIdleConnsPerHost: 100,
				IdleConnTimeout:     90 * time.Second,
			},
		},
		log: log,
		sem: make(chan struct{}, cfg.Concurrency),
	}, nil
}

// SendAll dispatches every message, bounded by Concurrency, and returns one
// result per input in the same order.
func (f *FCM) SendAll(ctx context.Context, msgs []Message) ([]Result, error) {
	results := make([]Result, len(msgs))
	if len(msgs) == 0 {
		return results, nil
	}

	token, err := f.ts.Token()
	if err != nil {
		return nil, fmt.Errorf("push: fetch access token: %w", err)
	}

	var wg sync.WaitGroup
	for i := range msgs {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			select {
			case f.sem <- struct{}{}:
				defer func() { <-f.sem }()
			case <-ctx.Done():
				results[idx] = Result{Retryable: true, Error: ctx.Err().Error()}
				return
			}
			results[idx] = f.sendOne(ctx, token.AccessToken, msgs[idx])
		}(i)
	}
	wg.Wait()

	return results, nil
}

// fcmEnvelope is the HTTP v1 request body.
type fcmEnvelope struct {
	ValidateOnly bool       `json:"validate_only,omitempty"`
	Message      fcmMessage `json:"message"`
}

type fcmMessage struct {
	Token        string            `json:"token"`
	Notification *fcmNotification  `json:"notification,omitempty"`
	Data         map[string]string `json:"data,omitempty"`
	Android      *fcmAndroid       `json:"android,omitempty"`
	APNS         *fcmAPNS          `json:"apns,omitempty"`
	Webpush      *fcmWebpush       `json:"webpush,omitempty"`
}

type fcmNotification struct {
	Title string `json:"title,omitempty"`
	Body  string `json:"body,omitempty"`
}

type fcmAndroid struct {
	Priority    string `json:"priority,omitempty"`
	CollapseKey string `json:"collapse_key,omitempty"`
	TTL         string `json:"ttl,omitempty"`
}

type fcmAPNS struct {
	Headers map[string]string `json:"headers,omitempty"`
	Payload map[string]any    `json:"payload,omitempty"`
}

type fcmWebpush struct {
	Headers map[string]string `json:"headers,omitempty"`
}

func (f *FCM) sendOne(ctx context.Context, accessToken string, m Message) Result {
	env := fcmEnvelope{
		ValidateOnly: f.cfg.DryRun,
		Message: fcmMessage{
			Token: m.Token,
			Data:  m.Data,
		},
	}
	// A notification block makes the OS render the alert itself. Omitting it
	// and sending data only would let the app decrypt and render the real
	// content — the right choice for secret chats, and why the pusher decides
	// per message whether to include a preview.
	if m.Title != "" || m.Body != "" {
		env.Message.Notification = &fcmNotification{Title: m.Title, Body: m.Body}
	}

	ttl := m.TTL
	if ttl == 0 {
		ttl = 24 * time.Hour
	}

	switch strings.ToLower(m.Platform) {
	case "ios":
		payload := map[string]any{
			"aps": map[string]any{
				"sound":             "default",
				"mutable-content":   1,
				"content-available": 1,
			},
		}
		if m.Badge > 0 {
			payload["aps"].(map[string]any)["badge"] = m.Badge
		}
		headers := map[string]string{
			"apns-priority":  "10",
			"apns-push-type": "alert",
			// APNs wants an absolute expiry in unix seconds.
			"apns-expiration": strconv.FormatInt(time.Now().Add(ttl).Unix(), 10),
		}
		if m.CollapseKey != "" {
			headers["apns-collapse-id"] = truncate(m.CollapseKey, 64)
		}
		env.Message.APNS = &fcmAPNS{Headers: headers, Payload: payload}

	case "web":
		env.Message.Webpush = &fcmWebpush{
			Headers: map[string]string{"TTL": strconv.Itoa(int(ttl.Seconds()))},
		}

	default: // android
		env.Message.Android = &fcmAndroid{
			Priority:    "high",
			CollapseKey: m.CollapseKey,
			TTL:         fmt.Sprintf("%ds", int(ttl.Seconds())),
		}
	}

	body, err := json.Marshal(env)
	if err != nil {
		return Result{Error: fmt.Sprintf("marshal: %v", err)}
	}

	url := fmt.Sprintf("https://fcm.googleapis.com/v1/projects/%s/messages:send", f.cfg.ProjectID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return Result{Error: fmt.Sprintf("build request: %v", err)}
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := f.client.Do(req)
	if err != nil {
		return Result{Retryable: true, Error: err.Error()}
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return Result{OK: true}
	}

	detail, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	msg := strings.TrimSpace(string(detail))

	switch resp.StatusCode {
	case http.StatusNotFound, http.StatusBadRequest:
		// 404 UNREGISTERED and 400 INVALID_ARGUMENT on the token both mean
		// the token will never work again. Anything else 400 is our bug, so
		// distinguish on the error body rather than the status alone.
		if strings.Contains(msg, "UNREGISTERED") ||
			strings.Contains(msg, "NOT_FOUND") ||
			strings.Contains(msg, "registration-token-not-registered") ||
			strings.Contains(msg, "INVALID_ARGUMENT") && strings.Contains(msg, "token") {
			return Result{Unregistered: true, Error: msg}
		}
		return Result{Error: fmt.Sprintf("%s: %s", resp.Status, msg)}

	case http.StatusUnauthorized, http.StatusForbidden:
		// A credentials problem is not per-message; surfacing it as
		// retryable keeps the consumer alive while an operator fixes IAM.
		return Result{Retryable: true, Error: fmt.Sprintf("%s: %s", resp.Status, msg)}

	case http.StatusTooManyRequests, http.StatusInternalServerError,
		http.StatusServiceUnavailable, http.StatusBadGateway:
		return Result{Retryable: true, Error: fmt.Sprintf("%s: %s", resp.Status, msg)}
	}

	return Result{Error: fmt.Sprintf("%s: %s", resp.Status, msg)}
}

// truncate caps a string at n bytes without splitting a character.
//
// Byte slicing alone would cut a multi-byte rune in half and produce invalid
// UTF-8. That matters here because the limits are byte limits imposed by APNs
// and FCM, while the content is arbitrary user text — Arabic, emoji, any
// script — so the cut point and the character boundary rarely coincide.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// Walk back to the start of the rune that straddles the boundary. At most
	// three steps, since UTF-8 encodes to four bytes at the widest.
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
