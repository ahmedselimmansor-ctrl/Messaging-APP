package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/pervagans/messaging-app/pkg/mtproto"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
)

// Upstream calls the services behind the gateway.
//
// Every call carries the caller's identity in X-User-Id / X-Device-Id rather
// than forwarding the client's token. The gateway has already authenticated
// the connection; re-verifying a JWT at every hop would add a signature check
// per message for no additional security, since the mesh already proves which
// workload is calling.
type Upstream struct {
	chatURL     string
	authURL     string
	presenceURL string
	client      *http.Client
	log         *slog.Logger
}

// NewUpstream builds the client.
func NewUpstream(cfg Config, log *slog.Logger) *Upstream {
	return &Upstream{
		chatURL:     cfg.ChatServiceURL,
		authURL:     cfg.AuthServiceURL,
		presenceURL: cfg.PresenceURL,
		client: &http.Client{
			// No global timeout: it is set per call, because a getDifference
			// over 500 chats legitimately takes longer than a send.
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					Timeout:   3 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				// The gateway makes one upstream call per client message, so
				// connection reuse is the difference between a handful of
				// sockets and one per request.
				MaxIdleConns:        512,
				MaxIdleConnsPerHost: 256,
				IdleConnTimeout:     90 * time.Second,
				ForceAttemptHTTP2:   true,
			},
		},
		log: log,
	}
}

// UpstreamError carries a failed upstream response.
type UpstreamError struct {
	Status     int
	Code       string
	Message    string
	RetryAfter int
}

func (e *UpstreamError) Error() string {
	return fmt.Sprintf("upstream %d %s: %s", e.Status, e.Code, e.Message)
}

// do performs a JSON call and decodes the response.
func (u *Upstream) do(ctx context.Context, method, endpoint string,
	userID, deviceID int64, body any, out any, timeout time.Duration) error {

	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("gateway: encode request: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return fmt.Errorf("gateway: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if userID != 0 {
		req.Header.Set("X-User-Id", strconv.FormatInt(userID, 10))
	}
	if deviceID != 0 {
		req.Header.Set("X-Device-Id", strconv.FormatInt(deviceID, 10))
	}
	// Propagate the trace so one client message is one trace from the socket
	// to Cassandra.
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(req.Header))

	resp, err := u.client.Do(req)
	if err != nil {
		return fmt.Errorf("gateway: call %s: %w", endpoint, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return decodeUpstreamError(resp)
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(out); err != nil {
		return fmt.Errorf("gateway: decode response from %s: %w", endpoint, err)
	}
	return nil
}

func decodeUpstreamError(resp *http.Response) error {
	var envelope struct {
		Error struct {
			Code       string `json:"code"`
			Message    string `json:"message"`
			RetryAfter int    `json:"retry_after"`
		} `json:"error"`
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	_ = json.Unmarshal(raw, &envelope)

	e := &UpstreamError{
		Status:     resp.StatusCode,
		Code:       envelope.Error.Code,
		Message:    envelope.Error.Message,
		RetryAfter: envelope.Error.RetryAfter,
	}
	if e.Code == "" {
		e.Code = http.StatusText(resp.StatusCode)
	}
	if e.RetryAfter == 0 {
		if v, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil {
			e.RetryAfter = v
		}
	}
	return e
}

// ---------------------------------------------------------------------------
// Auth service
// ---------------------------------------------------------------------------

// ResolveTokenRequest asks the auth service to validate a token and register
// the device.
type ResolveTokenRequest struct {
	AccessToken string `json:"access_token"`
	AuthKeyID   string `json:"auth_key_id,omitempty"`
	Platform    string `json:"platform,omitempty"`
	AppVersion  string `json:"app_version,omitempty"`
	DeviceModel string `json:"device_model,omitempty"`
	IP          string `json:"ip,omitempty"`
}

// ResolveTokenResponse is the resolved identity.
type ResolveTokenResponse struct {
	UserID      int64  `json:"user_id"`
	DeviceID    int64  `json:"device_id"`
	DisplayName string `json:"display_name"`
	LangCode    string `json:"lang_code"`
}

// ResolveToken validates an access token and registers the device.
func (u *Upstream) ResolveToken(ctx context.Context, req ResolveTokenRequest) (ResolveTokenResponse, error) {
	var out ResolveTokenResponse
	err := u.do(ctx, http.MethodPost, u.authURL+"/internal/v1/resolve-token",
		0, 0, req, &out, 5*time.Second)
	return out, err
}

// ---------------------------------------------------------------------------
// Chat service
// ---------------------------------------------------------------------------

// SendMessage forwards a send.
func (u *Upstream) SendMessage(ctx context.Context, userID, deviceID int64, req mtproto.SendMessage) (mtproto.SendMessageResult, error) {
	payload := map[string]any{
		"chat_id":      req.ChatID,
		"type":         req.Type,
		"body":         req.Body,
		"random_id":    req.RandomID,
		"reply_to_seq": req.ReplyToSeq,
		"encrypted":    req.Encrypted,
	}
	if req.MediaObject != "" {
		payload["media_object"] = req.MediaObject
		payload["media_mime"] = req.MediaMime
		payload["media_size"] = req.MediaSize
	}

	var out mtproto.SendMessageResult
	err := u.do(ctx, http.MethodPost, u.chatURL+"/internal/v1/messages",
		userID, deviceID, payload, &out, 10*time.Second)
	return out, err
}

// GetHistory forwards a history page request.
func (u *Upstream) GetHistory(ctx context.Context, userID, deviceID int64, req mtproto.GetHistory) (mtproto.GetHistoryResult, error) {
	q := url.Values{}
	q.Set("limit", strconv.Itoa(req.Limit))
	if req.BeforeSeq > 0 {
		q.Set("before_seq", strconv.FormatInt(req.BeforeSeq, 10))
	}
	endpoint := fmt.Sprintf("%s/internal/v1/chats/%d/messages?%s", u.chatURL, req.ChatID, q.Encode())

	var out mtproto.GetHistoryResult
	err := u.do(ctx, http.MethodGet, endpoint, userID, deviceID, nil, &out, 10*time.Second)
	return out, err
}

// GetDifference forwards a catch-up request.
func (u *Upstream) GetDifference(ctx context.Context, userID, deviceID int64, req mtproto.GetDifference) (mtproto.DifferenceResult, error) {
	var out mtproto.DifferenceResult
	// A generous timeout: this call fans out over every chat the client is
	// behind on, and it only happens once per reconnect.
	err := u.do(ctx, http.MethodPost, u.chatURL+"/internal/v1/difference",
		userID, deviceID, req, &out, 30*time.Second)
	return out, err
}

// ReadHistory forwards a read-pointer update.
func (u *Upstream) ReadHistory(ctx context.Context, userID, deviceID int64, req mtproto.ReadHistory) (mtproto.ReadHistoryResult, error) {
	endpoint := fmt.Sprintf("%s/internal/v1/chats/%d/read", u.chatURL, req.ChatID)
	var out mtproto.ReadHistoryResult
	err := u.do(ctx, http.MethodPost, endpoint, userID, deviceID,
		map[string]any{"chat_id": req.ChatID, "max_seq": req.MaxSeq}, &out, 5*time.Second)
	return out, err
}

// GetDialogs forwards a chat-list request.
func (u *Upstream) GetDialogs(ctx context.Context, userID, deviceID int64, req mtproto.GetDialogs) (mtproto.GetDialogsResult, error) {
	q := url.Values{}
	q.Set("limit", strconv.Itoa(req.Limit))
	q.Set("offset", strconv.Itoa(req.Offset))
	if req.IncludeArchived {
		q.Set("include_archived", "true")
	}

	var raw struct {
		Dialogs []struct {
			Chat struct {
				ID    int64  `json:"id"`
				Type  string `json:"type"`
				Title string `json:"title"`
			} `json:"chat"`
			MaxSeq      int64 `json:"max_seq"`
			LastReadSeq int64 `json:"last_read_seq"`
			UnreadCount int64 `json:"unread_count"`
			Pinned      bool  `json:"pinned"`
			Archived    bool  `json:"archived"`
			Peer        *struct {
				ID int64 `json:"id"`
			} `json:"peer"`
			MutedUntil *time.Time `json:"muted_until"`
		} `json:"dialogs"`
	}
	if err := u.do(ctx, http.MethodGet,
		u.chatURL+"/internal/v1/dialogs?"+q.Encode(),
		userID, deviceID, nil, &raw, 10*time.Second); err != nil {
		return mtproto.GetDialogsResult{}, err
	}

	out := mtproto.GetDialogsResult{Dialogs: make([]mtproto.DialogEntry, 0, len(raw.Dialogs))}
	for _, d := range raw.Dialogs {
		entry := mtproto.DialogEntry{
			ChatID: d.Chat.ID, Type: d.Chat.Type, Title: d.Chat.Title,
			MaxSeq: d.MaxSeq, LastReadSeq: d.LastReadSeq, UnreadCount: d.UnreadCount,
			Pinned: d.Pinned, Archived: d.Archived,
			Muted: d.MutedUntil != nil && d.MutedUntil.After(time.Now()),
		}
		if d.Peer != nil {
			entry.PeerID = d.Peer.ID
		}
		out.Dialogs = append(out.Dialogs, entry)
	}
	return out, nil
}

// SetTyping forwards a typing indicator.
func (u *Upstream) SetTyping(ctx context.Context, userID, deviceID int64, req mtproto.SetTyping) error {
	return u.do(ctx, http.MethodPost, u.chatURL+"/internal/v1/typing",
		userID, deviceID,
		map[string]any{"chat_id": req.ChatID, "action": req.Action},
		nil, 3*time.Second)
}

// MemberIDs returns a chat's roster, used when a session needs to subscribe
// to chat-scoped channels.
func (u *Upstream) MemberIDs(ctx context.Context, userID, deviceID, chatID int64) ([]int64, error) {
	var out struct {
		MemberIDs []int64 `json:"member_ids"`
	}
	endpoint := fmt.Sprintf("%s/internal/v1/chats/%d/members", u.chatURL, chatID)
	err := u.do(ctx, http.MethodGet, endpoint, userID, deviceID, nil, &out, 5*time.Second)
	return out.MemberIDs, err
}

// Ping checks the chat service is reachable; used as a readiness check.
func (u *Upstream) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.chatURL+"/healthz", nil)
	if err != nil {
		return err
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return fmt.Errorf("gateway: chat service unreachable: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("gateway: chat service health returned %s", resp.Status)
	}
	return nil
}
