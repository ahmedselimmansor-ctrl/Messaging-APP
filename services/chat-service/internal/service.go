package chat

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/pervagans/messaging-app/pkg/auditlog"
	"github.com/pervagans/messaging-app/pkg/authn"
	"github.com/pervagans/messaging-app/pkg/cassandrax"
	"github.com/pervagans/messaging-app/pkg/events"
	"github.com/pervagans/messaging-app/pkg/httpx"
	"github.com/pervagans/messaging-app/pkg/ids"
	"github.com/pervagans/messaging-app/pkg/kafkax"
	"github.com/pervagans/messaging-app/pkg/pgstore"
	"github.com/pervagans/messaging-app/pkg/ratelimit"
	"github.com/pervagans/messaging-app/pkg/redisx"
	"github.com/pervagans/messaging-app/pkg/telemetry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// Service holds the chat service's dependencies.
type Service struct {
	Cfg       Config
	Log       *slog.Logger
	Chats     *pgstore.Chats
	Members   *pgstore.Members
	Users     *pgstore.Users
	Sequences *pgstore.Sequences
	Messages  *cassandrax.MessageRepo
	Redis     *redisx.Client
	Seq       *redisx.SeqAllocator
	Bus       *redisx.Bus
	MemCache  *redisx.MembersCache
	Producer  *kafkax.Producer
	IDs       *ids.Snowflake
	// Verifier is the interface rather than *RefreshingVerifier: this service
	// only ever calls Verify, and depending on the narrower type lets a test
	// mount the real router without a JWKS endpoint to refresh from.
	Verifier    authn.TokenVerifier
	Limiter     *ratelimit.Limiter
	Audit       *auditlog.Logger
	Reports     *pgstore.Reports
	Devices     *pgstore.Devices
	Contacts    *pgstore.Contacts
	SecretChats *pgstore.SecretChats
	// Blocks is read directly for the data export only. The send path goes
	// through auth-service instead, because that owns the blocklist and caches
	// the answer; an export is a rare, one-off read where the extra hop buys
	// nothing. svc_chat holds the Postgres grant either way (migration 0002).
	Blocks   *pgstore.Blocks
	BanCache *redisx.Bans

	// regionClient carries proxied sends to a chat's home region. Built
	// lazily so a single-region deployment never allocates it.
	regionClient *http.Client
}

// Init prepares the derived state a Service needs before serving.
func (s *Service) Init() {
	s.regionClient = newRegionClient()
}

// Routes builds the HTTP surface.
//
// Two families: /v1 for authenticated clients (the web app and anything not
// on the realtime connection), and /internal/v1 for the realtime gateway,
// which has already authenticated the caller and passes the identity in a
// header. The mesh policy in deploy/k8s/mesh restricts /internal to the
// gateway's service account.
func (s *Service) Routes() http.Handler {
	r := chi.NewRouter()
	for _, mw := range httpx.BaseMiddleware("chat-service") {
		r.Use(mw)
	}

	r.Group(func(r chi.Router) {
		r.Use(authn.Middleware(s.Verifier))

		r.Get("/v1/dialogs", httpx.H(s.handleGetDialogs))
		r.Post("/v1/chats", httpx.H(s.handleCreateChat))
		r.Get("/v1/chats/{chatID}", httpx.H(s.handleGetChat))
		r.Patch("/v1/chats/{chatID}", httpx.H(s.handleUpdateChat))
		r.Get("/v1/chats/{chatID}/members", httpx.H(s.handleListMembers))
		r.Post("/v1/chats/{chatID}/members", httpx.H(s.handleAddMember))
		r.Delete("/v1/chats/{chatID}/members/{userID}", httpx.H(s.handleRemoveMember))
		r.Patch("/v1/chats/{chatID}/members/{userID}", httpx.H(s.handleSetRole))
		r.Delete("/v1/chats/{chatID}", httpx.H(s.handleDeleteChat))
		r.Post("/v1/chats/{chatID}/leave", httpx.H(s.handleLeave))
		r.Put("/v1/chats/{chatID}/mute", httpx.H(s.handleMute))

		r.Post("/v1/chats/{chatID}/messages", httpx.H(s.handleSendMessage))
		r.Get("/v1/chats/{chatID}/messages", httpx.H(s.handleGetHistory))
		r.Post("/v1/chats/{chatID}/read", httpx.H(s.handleMarkRead))
		r.Delete("/v1/chats/{chatID}/messages/{seq}", httpx.H(s.handleDeleteMessage))
		r.Patch("/v1/chats/{chatID}/messages/{seq}", httpx.H(s.handleEditMessage))
		r.Post("/v1/difference", httpx.H(s.handleGetDifference))
		r.Post("/v1/reports", httpx.H(s.handleReport))
		r.Get("/v1/me/export", httpx.H(s.handleExport))
	})

	// Internal surface for the realtime gateway.
	r.Group(func(r chi.Router) {
		r.Use(s.internalIdentity)

		r.Post("/internal/v1/messages", httpx.H(s.handleSendMessage))
		r.Get("/internal/v1/chats/{chatID}/messages", httpx.H(s.handleGetHistory))
		r.Post("/internal/v1/chats/{chatID}/read", httpx.H(s.handleMarkRead))
		r.Post("/internal/v1/difference", httpx.H(s.handleGetDifference))
		r.Get("/internal/v1/dialogs", httpx.H(s.handleGetDialogs))
		r.Post("/internal/v1/typing", httpx.H(s.handleTyping))
		r.Get("/internal/v1/chats/{chatID}/members", httpx.H(s.handleListMemberIDs))
	})

	return r
}

// internalIdentity trusts the gateway's assertion of who the caller is.
//
// This is safe only because the mesh enforces mTLS and an AuthorizationPolicy
// that lets nothing but the gateway reach /internal. If that policy were ever
// dropped, this header would be a complete authentication bypass — which is
// why the policy is part of the same kustomize base as the Deployment and not
// an optional add-on.
func (s *Service) internalIdentity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID := headerInt64(r, "X-User-Id")
		deviceID := headerInt64(r, "X-Device-Id")
		if userID == 0 {
			httpx.WriteError(w, r, httpx.ErrUnauthorized("X-User-Id is required on internal calls"))
			return
		}
		claims := &authn.Claims{Type: authn.AccessToken, UserID: userID, DeviceID: deviceID}
		next.ServeHTTP(w, r.WithContext(authn.WithClaims(r.Context(), claims)))
	})
}

// ---------------------------------------------------------------------------
// Sending
// ---------------------------------------------------------------------------

type sendMessageRequest struct {
	// ChatID is read from the path on the public route and from the body on
	// the internal one.
	ChatID     int64  `json:"chat_id,omitempty"`
	Type       string `json:"type"`
	Body       string `json:"body,omitempty"`
	RandomID   int64  `json:"random_id"`
	ReplyToSeq int64  `json:"reply_to_seq,omitempty"`

	MediaObject string `json:"media_object,omitempty"`
	MediaMime   string `json:"media_mime,omitempty"`
	MediaSize   int64  `json:"media_size,omitempty"`
	MediaWidth  int    `json:"media_width,omitempty"`
	MediaHeight int    `json:"media_height,omitempty"`
	MediaDurMS  int64  `json:"media_duration_ms,omitempty"`

	Encrypted bool `json:"encrypted,omitempty"`
}

type sendMessageResponse struct {
	MessageID string `json:"message_id"`
	ChatID    int64  `json:"chat_id"`
	Seq       int64  `json:"seq"`
	Date      int64  `json:"date"`
	Duplicate bool   `json:"duplicate,omitempty"`
}

// handleSendMessage is the platform's hot path.
//
// The ordering below is the whole design in miniature:
//
//  1. Rate limit, per user and per user-per-chat.
//  2. Refuse a banned sender, before they learn anything about the chat.
//  3. Authorise from cache (Redis), falling back to Postgres on a miss.
//  4. Deduplicate against the client's random id.
//  5. Allocate a dense sequence number (Redis INCR).
//  6. Publish to Kafka with acks=all — the message is durable *here*.
//  7. Fan out over Redis pub/sub to online recipients, and return the
//     sequence to the sender.
//
// Cassandra is not on this path. Persistence happens asynchronously in the
// persister consumer, because Kafka with acks=all is already the durability
// boundary and waiting for Cassandra as well would double send latency for no
// additional guarantee.
func (s *Service) handleSendMessage(w http.ResponseWriter, r *http.Request) error {
	started := time.Now()
	claims, ok := authn.ClaimsFrom(r.Context())
	if !ok {
		return httpx.ErrUnauthorized("authorization required")
	}

	var req sendMessageRequest
	if err := httpx.DecodeJSON(r, 1<<20, &req); err != nil {
		return err
	}
	chatID := req.ChatID
	if raw := chi.URLParam(r, "chatID"); raw != "" {
		var err error
		if chatID, err = httpx.PathInt64(r, "chatID"); err != nil {
			return err
		}
	}
	if chatID == 0 {
		return httpx.ErrBadRequest("chat_id is required")
	}

	msgType, err := s.validateSend(&req)
	if err != nil {
		return err
	}

	ctx := r.Context()
	tracer := otel.Tracer("chat-service")
	ctx, span := tracer.Start(ctx, "send_message")
	defer span.End()

	// 1. Rate limit: per user overall, and per user per chat so one busy
	//    conversation cannot consume the whole allowance.
	if err := s.checkLimit(ctx, ratelimit.KeyUser("send", claims.UserID), ratelimit.SendMessage); err != nil {
		return err
	}
	if err := s.checkLimit(ctx,
		ratelimit.KeyUserChat("send", claims.UserID, chatID), ratelimit.SendMessagePerChat); err != nil {
		return err
	}

	// 2. Refuse a banned sender.
	//
	//    Before authorisation, because a banned account should not learn
	//    whether a chat exists or who is in it. The authoritative check is at
	//    token issuance; this closes the window where a ban lands while an
	//    access token is still valid.
	if err := s.refuseIfBanned(ctx, claims.UserID); err != nil {
		return err
	}

	// 3. Authorise.
	recipients, err := s.authorisedRecipients(ctx, chatID, claims.UserID)
	if err != nil {
		return err
	}

	// 3b. Apply the blocklist. In a private chat a block refuses the send; in
	//     a group it drops the blocker from the fanout, because everyone else
	//     is still entitled to the message.
	chatMeta, err := s.Chats.Get(ctx, chatID)
	if err != nil {
		return httpx.ErrNotFound("no such chat")
	}

	// 3c. If this chat is homed in another region, the send belongs there.
	//     Sequence allocation must have a single writer per chat; handling it
	//     locally would mint a duplicate sequence number and overwrite
	//     history.
	//
	//     X-Proxied-From means a peer already forwarded this to us, so we
	//     handle it here regardless — otherwise a misconfiguration where two
	//     regions each believe the other owns the chat would bounce the
	//     request until it timed out.
	if !s.isLocal(chatMeta.HomeRegion) && r.Header.Get("X-Proxied-From") == "" {
		var proxied sendMessageResponse
		req.ChatID = chatID
		if err := s.proxyToHomeRegion(ctx, chatMeta.HomeRegion, "/internal/v1/messages",
			claims.UserID, claims.DeviceID, req, &proxied); err != nil {
			return err
		}
		httpx.WriteJSON(w, http.StatusOK, proxied)
		return nil
	}
	recipients, err = s.enforceBlocks(ctx, chatMeta, claims.UserID, recipients)
	if err != nil {
		return err
	}

	// 4. Deduplicate. A client that retried after a timeout must get the
	//    original message back, not create a second one.
	if req.RandomID != 0 {
		seq, messageID, err := s.Messages.FindByClientRandomID(ctx, chatID, claims.UserID, req.RandomID)
		switch {
		case err == nil:
			httpx.WriteJSON(w, http.StatusOK, sendMessageResponse{
				MessageID: messageID, ChatID: chatID, Seq: seq,
				Date: time.Now().Unix(), Duplicate: true,
			})
			return nil
		case errors.Is(err, cassandrax.ErrNotFound):
			// Not a retry; carry on.
		default:
			// A dedupe lookup failure must not block sending. The worst case
			// is a duplicate message, which is better than a failed send.
			s.Log.Warn("dedupe lookup failed, continuing", "chat_id", chatID, "error", err)
		}
	}

	// 5. Allocate the sequence.
	seq, err := s.Seq.Next(ctx, chatID)
	if err != nil {
		return httpx.ErrUnavailable("could not allocate a message sequence").WithCause(err)
	}

	evt := &events.MessageEvent{
		V:              events.CurrentVersion,
		MessageID:      ids.NewUUID(),
		ChatID:         chatID,
		Seq:            seq,
		SenderID:       claims.UserID,
		Type:           msgType,
		Body:           req.Body,
		Encrypted:      req.Encrypted,
		ReplyToSeq:     req.ReplyToSeq,
		ClientRandomID: req.RandomID,
		CreatedAt:      time.Now().UTC(),
		TraceParent:    traceParent(ctx),
	}
	if req.MediaObject != "" {
		evt.Media = &events.MediaRef{
			Object:     req.MediaObject,
			MimeType:   req.MediaMime,
			SizeBytes:  req.MediaSize,
			Width:      req.MediaWidth,
			Height:     req.MediaHeight,
			DurationMS: req.MediaDurMS,
		}
	}
	// Attaching the roster saves every downstream consumer a Postgres read.
	// For very large channels the list is omitted and consumers fall back to
	// reading it themselves, because a 200k-element array per message would
	// dwarf the message itself.
	if len(recipients) <= s.Cfg.MaxRecipientsInline {
		evt.Recipients = recipients
	}

	if err := evt.Validate(); err != nil {
		return httpx.ErrBadRequest("%v", err)
	}

	// 6. Publish. This is the durability boundary: once WriteMessages returns
	//    with acks=all, the leader and every in-sync replica hold the record.
	body, err := json.Marshal(evt)
	if err != nil {
		return httpx.ErrInternal("could not encode the message").WithCause(err)
	}
	if err := s.Producer.Publish(ctx, events.TopicMessagesRaw, chatKey(chatID), body); err != nil {
		// The sequence number is now burned. That is deliberate and harmless:
		// sequences must be monotonic, not gapless-under-failure, and the
		// client's retry will take the next one.
		return httpx.ErrUnavailable("could not accept the message").WithCause(err)
	}

	// 7. Fan out to whoever is connected right now. Best effort: a delivery
	//    that fails here is recovered by the client's catch-up on reconnect.
	s.fanout(ctx, evt, recipients)

	telemetry.ObserveRPC("http", "send_message", "200", started)
	httpx.WriteJSON(w, http.StatusOK, sendMessageResponse{
		MessageID: evt.MessageID,
		ChatID:    chatID,
		Seq:       seq,
		Date:      evt.CreatedAt.Unix(),
	})
	return nil
}

func (s *Service) validateSend(req *sendMessageRequest) (events.MessageType, error) {
	msgType := events.MessageType(strings.ToLower(strings.TrimSpace(req.Type)))
	if msgType == "" {
		msgType = events.MessageText
	}

	switch msgType {
	case events.MessageText:
		body := strings.TrimSpace(req.Body)
		if body == "" && !req.Encrypted {
			return "", httpx.ErrBadRequest("a text message needs a body")
		}
		if len([]rune(req.Body)) > s.Cfg.MaxMessageRunes {
			return "", httpx.ErrBadRequest("message exceeds %d characters", s.Cfg.MaxMessageRunes)
		}
	case events.MessagePhoto, events.MessageVideo, events.MessageVoice,
		events.MessageFile, events.MessageSticker:
		if req.MediaObject == "" {
			return "", httpx.ErrBadRequest("a %s message needs media_object", msgType)
		}
		if strings.Contains(req.MediaObject, "..") || strings.HasPrefix(req.MediaObject, "/") {
			return "", httpx.ErrBadRequest("media_object is not a valid object path")
		}
	case events.MessageSystem:
		return "", httpx.ErrForbidden("system messages cannot be sent by clients")
	default:
		return "", httpx.ErrBadRequest("unsupported message type %q", req.Type)
	}
	return msgType, nil
}

// authorisedRecipients checks membership and returns the roster.
//
// Cache first, database second, and the database result is written back — so
// a busy chat costs one Postgres query every MembersCacheTTL rather than one
// per message.
func (s *Service) authorisedRecipients(ctx context.Context, chatID, userID int64) ([]int64, error) {
	members, err := s.MemCache.Get(ctx, chatID)
	if err != nil {
		s.Log.Warn("member cache read failed", "chat_id", chatID, "error", err)
	}

	if len(members) > 0 {
		for _, id := range members {
			if id == userID {
				return members, nil
			}
		}
		// A cached roster that does not contain the sender is not proof of
		// denial — the cache may predate them joining. Fall through to the
		// database, which is authoritative.
	}

	isMember, canPost, err := s.Members.CanPost(ctx, chatID, userID)
	if err != nil {
		return nil, httpx.ErrInternal("membership lookup failed").WithCause(err)
	}
	if !isMember {
		// 404 rather than 403: confirming a chat exists to a non-member is an
		// enumeration oracle.
		return nil, httpx.ErrNotFound("no such chat")
	}
	if !canPost {
		return nil, httpx.ErrForbidden("you do not have permission to post in this chat")
	}

	members, err = s.Members.IDs(ctx, chatID)
	if err != nil {
		return nil, httpx.ErrInternal("member lookup failed").WithCause(err)
	}
	if err := s.MemCache.Set(ctx, chatID, members); err != nil {
		s.Log.Warn("member cache write failed", "chat_id", chatID, "error", err)
	}
	return members, nil
}

// fanout publishes the realtime update to every recipient's channel.
func (s *Service) fanout(ctx context.Context, evt *events.MessageEvent, recipients []int64) {
	payload, err := json.Marshal(toHistoryMessage(evt))
	if err != nil {
		s.Log.Error("could not encode the fanout payload", "error", err)
		return
	}

	update := redisx.Update{
		Kind:   redisx.UpdateNewMessage,
		ChatID: evt.ChatID,
		Seq:    evt.Seq,
		UserID: evt.SenderID,
		At:     evt.CreatedAt.UnixMilli(),
		Body:   payload,
	}

	// Fanout must not block the caller's response. Using a detached context
	// means a client that hangs up mid-request still gets its message
	// delivered to everyone else.
	go func() {
		fanCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		if err := s.Bus.PublishToUsers(fanCtx, recipients, update); err != nil {
			s.Log.Warn("realtime fanout failed", "chat_id", evt.ChatID, "error", err)
			return
		}
		telemetry.MessagesDelivered.WithLabelValues("realtime").Add(float64(len(recipients)))
	}()
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

func (s *Service) handleGetHistory(w http.ResponseWriter, r *http.Request) error {
	claims, ok := authn.ClaimsFrom(r.Context())
	if !ok {
		return httpx.ErrUnauthorized("authorization required")
	}
	chatID, err := httpx.PathInt64(r, "chatID")
	if err != nil {
		return err
	}

	if err := s.checkLimit(r.Context(),
		ratelimit.KeyUser("read", claims.UserID), ratelimit.APIReadPerUser); err != nil {
		return err
	}
	if _, err := s.requireMember(r.Context(), chatID, claims.UserID); err != nil {
		return err
	}

	beforeSeq := httpx.QueryInt64(r, "before_seq", 0)
	limit := httpx.QueryInt(r, "limit", 50, 1, 200)

	rows, err := s.Messages.History(r.Context(), chatID, beforeSeq, limit)
	if err != nil {
		return httpx.ErrInternal("history lookup failed").WithCause(err)
	}

	out := make([]historyMessage, 0, len(rows))
	for _, m := range rows {
		out = append(out, fromStored(m))
	}
	var next int64
	if len(out) == limit && len(out) > 0 {
		next = out[len(out)-1].Seq
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"messages":        out,
		"next_before_seq": next,
	})
	return nil
}

type differenceRequest struct {
	Cursors map[int64]int64 `json:"cursors"`
	Limit   int             `json:"limit"`
}

// handleGetDifference is the reconnect catch-up.
//
// This is what makes the fire-and-forget realtime layer safe: whatever the
// client missed while its connection was down is read back out of Cassandra
// from the last sequence it holds.
func (s *Service) handleGetDifference(w http.ResponseWriter, r *http.Request) error {
	claims, ok := authn.ClaimsFrom(r.Context())
	if !ok {
		return httpx.ErrUnauthorized("authorization required")
	}
	var req differenceRequest
	if err := httpx.DecodeJSON(r, 256<<10, &req); err != nil {
		return err
	}
	if len(req.Cursors) == 0 {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"messages": []historyMessage{}, "new_cursors": map[int64]int64{},
		})
		return nil
	}
	if len(req.Cursors) > 500 {
		return httpx.ErrBadRequest("at most 500 chat cursors per request")
	}
	limit := req.Limit
	if limit <= 0 || limit > 1000 {
		limit = 300
	}

	if err := s.checkLimit(r.Context(),
		ratelimit.KeyUser("read", claims.UserID), ratelimit.APIReadPerUser); err != nil {
		return err
	}

	// Establish which of the requested chats the caller is actually in. A
	// client that asks for a chat it left, or never joined, gets nothing —
	// silently, so the response cannot be used to probe for chat existence.
	dialogs, err := s.Members.Dialogs(r.Context(), claims.UserID, true, 500, 0)
	if err != nil {
		return httpx.ErrInternal("dialog lookup failed").WithCause(err)
	}
	allowed := make(map[int64]int64, len(dialogs))
	for _, d := range dialogs {
		allowed[d.Chat.ID] = d.MaxSeq
	}

	out := make([]historyMessage, 0, limit)
	newCursors := make(map[int64]int64, len(req.Cursors))
	truncated := false

	for chatID, since := range req.Cursors {
		maxSeq, ok := allowed[chatID]
		if !ok {
			continue
		}
		newCursors[chatID] = since
		if maxSeq <= since {
			newCursors[chatID] = maxSeq
			continue
		}
		if len(out) >= limit {
			truncated = true
			continue
		}

		rows, err := s.Messages.Range(r.Context(), chatID, since+1, maxSeq, limit-len(out))
		if err != nil {
			s.Log.Warn("difference range failed", "chat_id", chatID, "error", err)
			continue
		}
		for _, m := range rows {
			out = append(out, fromStored(m))
			newCursors[chatID] = m.Seq
		}
		if newCursors[chatID] < maxSeq {
			truncated = true
		}
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"messages":    out,
		"truncated":   truncated,
		"new_cursors": newCursors,
	})
	return nil
}

func (s *Service) handleGetDialogs(w http.ResponseWriter, r *http.Request) error {
	claims, ok := authn.ClaimsFrom(r.Context())
	if !ok {
		return httpx.ErrUnauthorized("authorization required")
	}

	includeArchived := r.URL.Query().Get("include_archived") == "true"
	limit := httpx.QueryInt(r, "limit", 50, 1, 200)
	offset := httpx.QueryInt(r, "offset", 0, 0, 100_000)

	dialogs, err := s.Members.Dialogs(r.Context(), claims.UserID, includeArchived, limit, offset)
	if err != nil {
		return httpx.ErrInternal("dialog lookup failed").WithCause(err)
	}

	// Hydrate the other party's profile for private chats, in one batch.
	peerIDs := make([]int64, 0, len(dialogs))
	privateChats := make([]int, 0, len(dialogs))
	for i, d := range dialogs {
		if d.Chat.Type == pgstore.ChatPrivate {
			privateChats = append(privateChats, i)
		}
	}
	if len(privateChats) > 0 {
		for _, i := range privateChats {
			members, err := s.Members.IDs(r.Context(), dialogs[i].Chat.ID)
			if err != nil {
				continue
			}
			for _, id := range members {
				if id != claims.UserID {
					peerIDs = append(peerIDs, id)
					break
				}
			}
		}
		peers, err := s.Users.GetMany(r.Context(), peerIDs)
		if err == nil {
			pi := 0
			for _, i := range privateChats {
				if pi < len(peerIDs) {
					if u, ok := peers[peerIDs[pi]]; ok {
						dialogs[i].Peer = &u
						if dialogs[i].Chat.Title == "" {
							dialogs[i].Chat.Title = u.DisplayName
						}
					}
					pi++
				}
			}
		}
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{"dialogs": dialogs})
	return nil
}

// ---------------------------------------------------------------------------
// Read receipts, edits, deletes
// ---------------------------------------------------------------------------

type markReadRequest struct {
	ChatID int64 `json:"chat_id,omitempty"`
	MaxSeq int64 `json:"max_seq"`
}

func (s *Service) handleMarkRead(w http.ResponseWriter, r *http.Request) error {
	claims, ok := authn.ClaimsFrom(r.Context())
	if !ok {
		return httpx.ErrUnauthorized("authorization required")
	}
	var req markReadRequest
	if err := httpx.DecodeJSON(r, 4<<10, &req); err != nil {
		return err
	}
	chatID := req.ChatID
	if raw := chi.URLParam(r, "chatID"); raw != "" {
		var err error
		if chatID, err = httpx.PathInt64(r, "chatID"); err != nil {
			return err
		}
	}
	if chatID == 0 || req.MaxSeq <= 0 {
		return httpx.ErrBadRequest("chat_id and a positive max_seq are required")
	}

	member, err := s.requireMember(r.Context(), chatID, claims.UserID)
	if err != nil {
		return err
	}
	_ = member

	newSeq, err := s.Members.MarkRead(r.Context(), chatID, claims.UserID, req.MaxSeq)
	if err != nil {
		return httpx.ErrInternal("could not update the read pointer").WithCause(err)
	}
	maxSeq, err := s.Sequences.Max(r.Context(), chatID)
	if err != nil {
		s.Log.Warn("sequence lookup failed", "chat_id", chatID, "error", err)
	}
	unread := int64(0)
	if maxSeq > newSeq {
		unread = maxSeq - newSeq
	}

	// Tell the other participants, so "seen" ticks appear without a poll.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		members, err := s.MemCache.Get(ctx, chatID)
		if err != nil || len(members) == 0 {
			if members, err = s.Members.IDs(ctx, chatID); err != nil {
				return
			}
		}
		_ = s.Bus.PublishToUsers(ctx, members, redisx.Update{
			Kind: redisx.UpdateReadReceipt, ChatID: chatID, Seq: newSeq, UserID: claims.UserID,
		})
	}()

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"chat_id":       chatID,
		"last_read_seq": newSeq,
		"unread_count":  unread,
	})
	return nil
}

func (s *Service) handleDeleteMessage(w http.ResponseWriter, r *http.Request) error {
	claims, ok := authn.ClaimsFrom(r.Context())
	if !ok {
		return httpx.ErrUnauthorized("authorization required")
	}
	chatID, err := httpx.PathInt64(r, "chatID")
	if err != nil {
		return err
	}
	seq, err := httpx.PathInt64(r, "seq")
	if err != nil {
		return err
	}

	member, err := s.requireMember(r.Context(), chatID, claims.UserID)
	if err != nil {
		return err
	}

	msg, err := s.messageAt(r.Context(), chatID, seq)
	if err != nil {
		return err
	}
	moderation, err := canDeleteMessage(member, msg.SenderID)
	if err != nil {
		return err
	}

	if err := s.Messages.SoftDelete(r.Context(), chatID, seq); err != nil {
		return httpx.ErrInternal("could not delete the message").WithCause(err)
	}
	s.publishUpdate(r.Context(), chatID, redisx.Update{
		Kind: redisx.UpdateDeleteMessage, ChatID: chatID, Seq: seq, UserID: claims.UserID,
	})

	// Only moderation is audited. Deleting your own message is an ordinary
	// user action and recording every one of them would bury the handful of
	// entries that matter under millions that do not.
	if moderation {
		s.audit(r.Context(), r, auditlog.Entry{
			Action:     auditlog.ActionMessageDeleted,
			ActorID:    claims.UserID,
			TargetType: "message",
			TargetID:   seq,
			Detail: map[string]string{
				"chat_id":    strconv.FormatInt(chatID, 10),
				"sender_id":  strconv.FormatInt(msg.SenderID, 10),
				"actor_role": string(member.Role),
			},
		})
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]bool{"deleted": true})
	return nil
}

type editMessageRequest struct {
	Body string `json:"body"`
}

func (s *Service) handleEditMessage(w http.ResponseWriter, r *http.Request) error {
	claims, ok := authn.ClaimsFrom(r.Context())
	if !ok {
		return httpx.ErrUnauthorized("authorization required")
	}
	chatID, err := httpx.PathInt64(r, "chatID")
	if err != nil {
		return err
	}
	seq, err := httpx.PathInt64(r, "seq")
	if err != nil {
		return err
	}
	var req editMessageRequest
	if err := httpx.DecodeJSON(r, 1<<20, &req); err != nil {
		return err
	}
	if strings.TrimSpace(req.Body) == "" {
		return httpx.ErrBadRequest("body cannot be empty; delete the message instead")
	}
	if len([]rune(req.Body)) > s.Cfg.MaxMessageRunes {
		return httpx.ErrBadRequest("message exceeds %d characters", s.Cfg.MaxMessageRunes)
	}

	if _, err := s.requireMember(r.Context(), chatID, claims.UserID); err != nil {
		return err
	}
	msg, err := s.messageAt(r.Context(), chatID, seq)
	if err != nil {
		return err
	}
	if msg.SenderID != claims.UserID {
		return httpx.ErrForbidden("you can only edit your own messages")
	}
	if msg.Deleted {
		return httpx.ErrNotFound("this message has been deleted")
	}

	now := time.Now().UTC()
	if err := s.Messages.Edit(r.Context(), chatID, seq, req.Body, now); err != nil {
		return httpx.ErrInternal("could not edit the message").WithCause(err)
	}

	payload, _ := json.Marshal(map[string]any{"body": req.Body, "edited_at": now})
	s.publishUpdate(r.Context(), chatID, redisx.Update{
		Kind: redisx.UpdateEditMessage, ChatID: chatID, Seq: seq,
		UserID: claims.UserID, Body: payload,
	})

	httpx.WriteJSON(w, http.StatusOK, map[string]any{"seq": seq, "edited_at": now})
	return nil
}

type typingRequest struct {
	ChatID int64  `json:"chat_id"`
	Action string `json:"action"`
}

// handleTyping publishes an ephemeral typing indicator.
//
// It never touches durable storage. Typing state is worthless a few seconds
// later, so writing it anywhere would be pure cost.
func (s *Service) handleTyping(w http.ResponseWriter, r *http.Request) error {
	claims, ok := authn.ClaimsFrom(r.Context())
	if !ok {
		return httpx.ErrUnauthorized("authorization required")
	}
	var req typingRequest
	if err := httpx.DecodeJSON(r, 1<<10, &req); err != nil {
		return err
	}
	if req.ChatID == 0 {
		return httpx.ErrBadRequest("chat_id is required")
	}

	members, err := s.MemCache.Get(r.Context(), req.ChatID)
	if err != nil || len(members) == 0 {
		if members, err = s.Members.IDs(r.Context(), req.ChatID); err != nil {
			return httpx.ErrNotFound("no such chat")
		}
	}
	inChat := false
	others := make([]int64, 0, len(members))
	for _, id := range members {
		if id == claims.UserID {
			inChat = true
			continue
		}
		others = append(others, id)
	}
	if !inChat {
		return httpx.ErrNotFound("no such chat")
	}

	payload, _ := json.Marshal(map[string]string{"action": orDefault(req.Action, "typing")})
	if err := s.Bus.PublishToUsers(r.Context(), others, redisx.Update{
		Kind: redisx.UpdateTyping, ChatID: req.ChatID, UserID: claims.UserID, Body: payload,
	}); err != nil {
		s.Log.Warn("typing fanout failed", "chat_id", req.ChatID, "error", err)
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
	return nil
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func (s *Service) requireMember(ctx context.Context, chatID, userID int64) (pgstore.Member, error) {
	member, err := s.Members.Get(ctx, chatID, userID)
	if err != nil {
		if errors.Is(err, pgstore.ErrNotFound) {
			return pgstore.Member{}, httpx.ErrNotFound("no such chat")
		}
		return pgstore.Member{}, httpx.ErrInternal("membership lookup failed").WithCause(err)
	}
	if member.LeftAt != nil {
		return pgstore.Member{}, httpx.ErrNotFound("no such chat")
	}
	return member, nil
}

func (s *Service) messageAt(ctx context.Context, chatID, seq int64) (cassandrax.StoredMessage, error) {
	rows, err := s.Messages.Range(ctx, chatID, seq, seq, 1)
	if err != nil {
		return cassandrax.StoredMessage{}, httpx.ErrInternal("message lookup failed").WithCause(err)
	}
	if len(rows) == 0 {
		return cassandrax.StoredMessage{}, httpx.ErrNotFound("no such message")
	}
	return rows[0], nil
}

func (s *Service) publishUpdate(ctx context.Context, chatID int64, u redisx.Update) {
	go func() {
		bg, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		members, err := s.MemCache.Get(bg, chatID)
		if err != nil || len(members) == 0 {
			if members, err = s.Members.IDs(bg, chatID); err != nil {
				return
			}
		}
		if err := s.Bus.PublishToUsers(bg, members, u); err != nil {
			s.Log.Warn("update fanout failed", "chat_id", chatID, "kind", u.Kind, "error", err)
		}
	}()
	_ = ctx
}

func (s *Service) checkLimit(ctx context.Context, key string, lim ratelimit.Limit) error {
	d, err := s.Limiter.AllowN(ctx, key, lim, 1)
	if err != nil {
		// Fail-open limiter: log and continue rather than reject.
		s.Log.Warn("rate limiter unavailable, allowing", "key", key, "error", err)
		return nil
	}
	if !d.Allowed {
		return httpx.ErrFloodWait(int(d.RetryAfter.Seconds()) + 1)
	}
	return nil
}

// chatKey is the Kafka partition key: all messages of one chat land on one
// partition, which is what preserves their order end to end.
func chatKey(chatID int64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(chatID))
	return b[:]
}

// traceParent renders the current span in W3C form so the trace survives the
// hop through Kafka.
func traceParent(ctx context.Context) string {
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() {
		return ""
	}
	carrier := propagation.MapCarrier{}
	otel.GetTextMapPropagator().Inject(ctx, carrier)
	return carrier.Get("traceparent")
}

func headerInt64(r *http.Request, name string) int64 {
	raw := r.Header.Get(name)
	if raw == "" {
		return 0
	}
	var v int64
	if _, err := fmt.Sscanf(raw, "%d", &v); err != nil {
		return 0
	}
	return v
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}
