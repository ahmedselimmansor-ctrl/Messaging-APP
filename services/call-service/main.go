// Command call-service coordinates voice and video calls.
//
// Signalling only. It relays SDP offers, answers and ICE candidates between
// two devices, and issues time-limited TURN credentials. No media ever
// touches our servers: the peers connect directly, or through TURN when a NAT
// refuses that.
//
// That is a deliberate architectural choice with a real trade. A selective
// forwarding unit would give us group calls, server-side recording and better
// behaviour on bad networks — and it would mean carrying every call's
// bandwidth and being able to listen to every call. Peer-to-peer keeps the
// bandwidth bill and the privacy posture where they belong.
//
// The consequence, stated plainly: group calls are not supported by this
// design, and adding them means adding an SFU.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/pervagans/messaging-app/pkg/app"
	"github.com/pervagans/messaging-app/pkg/authn"
	"github.com/pervagans/messaging-app/pkg/config"
	"github.com/pervagans/messaging-app/pkg/httpx"
	"github.com/pervagans/messaging-app/pkg/ids"
	"github.com/pervagans/messaging-app/pkg/mtproto"
	"github.com/pervagans/messaging-app/pkg/ratelimit"
	"github.com/pervagans/messaging-app/pkg/redisx"
	"github.com/pervagans/messaging-app/pkg/turn"
)

func main() {
	app.Run("call-service", run)
}

type service struct {
	redis    *redisx.Client
	bus      *redisx.Bus
	presence *redisx.Presence
	turn     *turn.Issuer
	ids      *ids.Snowflake
	limiter  *ratelimit.Limiter
}

// callTTL bounds how long call state survives.
//
// A call is a short-lived thing. Anything older than this is a call whose
// participants have long since given up, and keeping it would mean a client
// could "answer" a call from yesterday.
const callTTL = 5 * time.Minute

func run(ctx context.Context, a *app.App) error {
	rdb, err := redisx.Connect(ctx, redisx.Config{
		Addrs:    config.Strings("REDIS_ADDRS", []string{"localhost:6379"}),
		Cluster:  config.Bool("REDIS_CLUSTER", false),
		Username: config.String("REDIS_USERNAME", ""),
		Password: config.Secret("REDIS_PASSWORD", ""),
		TLS:      config.Bool("REDIS_TLS", false),
	})
	if err != nil {
		return fmt.Errorf("redis: %w", err)
	}
	a.OnShutdown("redis", rdb.Close)
	a.Health.Register("redis", rdb.Ping)

	turnCfg := turn.DefaultConfig()
	turnCfg.Secret = []byte(config.Secret("TURN_SECRET", ""))
	turnCfg.URIs = config.Strings("TURN_URIS", nil)
	turnCfg.STUNURIs = config.Strings("STUN_URIS", []string{"stun:stun.l.google.com:19302"})
	turnCfg.TTL = config.Duration("TURN_CREDENTIAL_TTL", 12*time.Hour)

	issuer, err := turn.NewIssuer(turnCfg)
	if err != nil {
		if errors.Is(err, turn.ErrNoSecret) && a.Cfg.Env == "dev" {
			// Without TURN, calls work only between peers that can reach each
			// other directly. That is fine on a laptop and useless in
			// production, so it is allowed here and refused there.
			a.Log.Warn("no TURN secret configured; calls will fail behind symmetric NATs")
			issuer = nil
		} else {
			return fmt.Errorf("turn: %w", err)
		}
	}

	snowflake, err := ids.NewSnowflake(ids.NodeFromHostname(config.String("HOSTNAME", "call-0")))
	if err != nil {
		return fmt.Errorf("id generator: %w", err)
	}

	svc := &service{
		redis:    rdb,
		bus:      rdb.PubSub(),
		presence: rdb.PresenceOf(config.Duration("PRESENCE_TTL", 90*time.Second)),
		turn:     issuer,
		ids:      snowflake,
		// Fail closed. Call setup is expensive for the callee — it rings
		// their phone — so an unbounded rate is a harassment tool.
		limiter: ratelimit.New(rdb.Raw(), false),
	}

	srv := httpx.NewServer(a.Cfg.HTTPAddr, svc.routes())
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			a.Log.Error("http listener failed", "error", err)
		}
	}()
	a.OnShutdown("http", srv.Shutdown)

	return nil
}

func (s *service) routes() http.Handler {
	r := chi.NewRouter()
	for _, mw := range httpx.BaseMiddleware("call-service") {
		r.Use(mw)
	}

	// Calls are driven entirely over the realtime connection, so every route
	// here is internal and the gateway asserts the caller's identity.
	r.Group(func(r chi.Router) {
		r.Use(s.internalIdentity)
		r.Post("/internal/v1/calls/request", httpx.H(s.handleRequest))
		r.Post("/internal/v1/calls/accept", httpx.H(s.handleAccept))
		r.Post("/internal/v1/calls/confirm", httpx.H(s.handleConfirm))
		r.Post("/internal/v1/calls/discard", httpx.H(s.handleDiscard))
		r.Post("/internal/v1/calls/signal", httpx.H(s.handleSignal))
		r.Get("/internal/v1/calls/turn", httpx.H(s.handleTURNCredentials))
	})

	return r
}

func (s *service) internalIdentity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var userID, deviceID int64
		_, _ = fmt.Sscanf(r.Header.Get("X-User-Id"), "%d", &userID)
		_, _ = fmt.Sscanf(r.Header.Get("X-Device-Id"), "%d", &deviceID)
		if userID == 0 {
			httpx.WriteError(w, r, httpx.ErrUnauthorized("X-User-Id is required on internal calls"))
			return
		}
		claims := &authn.Claims{Type: authn.AccessToken, UserID: userID, DeviceID: deviceID}
		next.ServeHTTP(w, r.WithContext(authn.WithClaims(r.Context(), claims)))
	})
}

// callState is what the server knows about a call in progress.
//
// Note the absence of anything that could decrypt the media: the DH public
// values pass through, and the key is derived on the two devices.
type callState struct {
	ID       int64  `json:"id"`
	CallerID int64  `json:"caller_id"`
	CalleeID int64  `json:"callee_id"`
	State    string `json:"state"`
	Video    bool   `json:"video"`

	// GAHash is the caller's commitment, published before GA.
	//
	// The commitment is what stops the callee — who chooses its value second,
	// after seeing nothing — from picking a value that steers the shared key.
	// Publishing a hash first removes that freedom.
	GAHash string `json:"g_a_hash,omitempty"`
	GA     string `json:"g_a,omitempty"`
	GB     string `json:"g_b,omitempty"`

	KeyFingerprint int64      `json:"key_fingerprint,omitempty"`
	StartedAt      time.Time  `json:"started_at"`
	AcceptedAt     *time.Time `json:"accepted_at,omitempty"`
}

func callKey(id int64) string { return fmt.Sprintf("call:{%d}", id) }

// activeCallKey enforces one call at a time per user. Without it a client
// could ring twenty people simultaneously.
func activeCallKey(userID int64) string { return fmt.Sprintf("callactive:{u%d}", userID) }

var (
	// callRequestLimit: five attempts, then one per two minutes. Ringing
	// someone's phone repeatedly is harassment, not a product feature.
	callRequestLimit = ratelimit.Limit{Burst: 5, Rate: 1.0 / 120.0}
	// signalLimit is generous: ICE candidate gathering is genuinely chatty.
	signalLimit = ratelimit.Limit{Burst: 200, Rate: 20}
)

func (s *service) handleRequest(w http.ResponseWriter, r *http.Request) error {
	claims, _ := authn.ClaimsFrom(r.Context())

	var req mtproto.RequestCall
	if err := httpx.DecodeJSON(r, 16<<10, &req); err != nil {
		return err
	}
	if req.PeerID == 0 || req.PeerID == claims.UserID {
		return httpx.ErrBadRequest("a valid peer_id is required")
	}
	if req.GAHash == "" {
		return httpx.ErrBadRequest("g_a_hash is required")
	}

	if d, err := s.limiter.Allow(r.Context(),
		ratelimit.KeyUser("call_request", claims.UserID), callRequestLimit); err != nil {
		return httpx.ErrUnavailable("service temporarily unavailable")
	} else if !d.Allowed {
		return httpx.ErrFloodWait(int(d.RetryAfter.Seconds()) + 1)
	}

	// One call at a time, each way. SetNX is the whole check: whoever wins
	// the key owns the call.
	callID := s.ids.Next()
	ok, err := s.redis.Raw().SetNX(r.Context(),
		activeCallKey(claims.UserID), callID, callTTL).Result()
	if err != nil {
		return httpx.ErrUnavailable("could not start the call").WithCause(err)
	}
	if !ok {
		return httpx.ErrConflict("you are already in a call")
	}

	if ok, err := s.redis.Raw().SetNX(r.Context(),
		activeCallKey(req.PeerID), callID, callTTL).Result(); err != nil || !ok {
		// Release our own slot, or the caller is stuck until the TTL expires.
		s.redis.Raw().Del(r.Context(), activeCallKey(claims.UserID))
		if err != nil {
			return httpx.ErrUnavailable("could not start the call").WithCause(err)
		}
		return httpx.ErrConflict("that user is already in a call")
	}

	online, err := s.presence.IsOnline(r.Context(), req.PeerID)
	if err == nil && !online {
		// Nothing to ring. The caller is told immediately rather than
		// listening to a ringtone for thirty seconds.
		s.releaseCall(r.Context(), claims.UserID, req.PeerID)
		return httpx.ErrConflict("that user is not available")
	}

	state := callState{
		ID: callID, CallerID: claims.UserID, CalleeID: req.PeerID,
		State: mtproto.CallStateRequested, Video: req.Video,
		GAHash: req.GAHash, StartedAt: time.Now().UTC(),
	}
	if err := s.saveCall(r.Context(), state); err != nil {
		s.releaseCall(r.Context(), claims.UserID, req.PeerID)
		return httpx.ErrUnavailable("could not record the call").WithCause(err)
	}

	s.notify(r.Context(), req.PeerID, mtproto.CallStateUpdate{
		CallID: callID, State: mtproto.CallStateRinging,
		PeerID: claims.UserID, Video: req.Video, GAHash: req.GAHash,
		Protocol: &req.Protocol,
	})

	httpx.WriteJSON(w, http.StatusOK, state)
	return nil
}

func (s *service) handleAccept(w http.ResponseWriter, r *http.Request) error {
	claims, _ := authn.ClaimsFrom(r.Context())

	var req mtproto.AcceptCall
	if err := httpx.DecodeJSON(r, 16<<10, &req); err != nil {
		return err
	}

	state, err := s.loadCall(r.Context(), req.CallID)
	if err != nil {
		return httpx.ErrNotFound("no such call")
	}
	// Only the callee may accept.
	if state.CalleeID != claims.UserID {
		return httpx.ErrForbidden("you are not the recipient of this call")
	}
	if state.State != mtproto.CallStateRequested {
		return httpx.ErrConflict("this call is no longer waiting to be answered")
	}
	if req.GB == "" {
		return httpx.ErrBadRequest("g_b is required")
	}

	now := time.Now().UTC()
	state.GB = req.GB
	state.State = mtproto.CallStateActive
	state.AcceptedAt = &now

	if err := s.saveCall(r.Context(), state); err != nil {
		return httpx.ErrUnavailable("could not update the call").WithCause(err)
	}

	// The caller now reveals the value it committed to.
	s.notify(r.Context(), state.CallerID, mtproto.CallStateUpdate{
		CallID: state.ID, State: mtproto.CallStateActive,
		PeerID: claims.UserID, GB: req.GB, Protocol: &req.Protocol,
	})

	httpx.WriteJSON(w, http.StatusOK, state)
	return nil
}

// handleConfirm carries the caller's g_a, which the callee checks against the
// hash it was given at ring time.
func (s *service) handleConfirm(w http.ResponseWriter, r *http.Request) error {
	claims, _ := authn.ClaimsFrom(r.Context())

	var req mtproto.ConfirmCall
	if err := httpx.DecodeJSON(r, 16<<10, &req); err != nil {
		return err
	}

	state, err := s.loadCall(r.Context(), req.CallID)
	if err != nil {
		return httpx.ErrNotFound("no such call")
	}
	if state.CallerID != claims.UserID {
		return httpx.ErrForbidden("only the caller can confirm")
	}
	if req.GA == "" {
		return httpx.ErrBadRequest("g_a is required")
	}

	state.GA = req.GA
	state.KeyFingerprint = req.KeyFingerprint
	if err := s.saveCall(r.Context(), state); err != nil {
		return httpx.ErrUnavailable("could not update the call").WithCause(err)
	}

	// The callee verifies SHA256(g_a) against the commitment itself. The
	// server relays both and checks neither: it has no stake in the outcome
	// and validating here would suggest a guarantee it cannot make.
	s.notify(r.Context(), state.CalleeID, mtproto.CallStateUpdate{
		CallID: state.ID, State: mtproto.CallStateActive,
		PeerID: claims.UserID, GA: req.GA,
	})

	httpx.WriteJSON(w, http.StatusOK, state)
	return nil
}

// handleSignal relays one SDP or ICE message.
//
// The payload is opaque. The server checks only that the sender is a party to
// the call — which is the entire security model of a signalling relay.
func (s *service) handleSignal(w http.ResponseWriter, r *http.Request) error {
	claims, _ := authn.ClaimsFrom(r.Context())

	var req mtproto.CallSignal
	if err := httpx.DecodeJSON(r, 256<<10, &req); err != nil {
		return err
	}

	state, err := s.loadCall(r.Context(), req.CallID)
	if err != nil {
		return httpx.ErrNotFound("no such call")
	}

	var peer int64
	switch claims.UserID {
	case state.CallerID:
		peer = state.CalleeID
	case state.CalleeID:
		peer = state.CallerID
	default:
		return httpx.ErrForbidden("you are not a party to this call")
	}

	if d, err := s.limiter.Allow(r.Context(),
		ratelimit.KeyUser("call_signal", claims.UserID), signalLimit); err == nil && !d.Allowed {
		return httpx.ErrFloodWait(1)
	}

	payload, _ := json.Marshal(map[string]any{
		"call_id": req.CallID, "kind": req.Kind, "payload": req.Payload,
	})
	if err := s.bus.Publish(r.Context(), redisx.ChannelUser(peer), redisx.Update{
		Kind: "call_signal", UserID: claims.UserID, Body: payload,
	}); err != nil {
		return httpx.ErrUnavailable("could not relay the signal").WithCause(err)
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
	return nil
}

func (s *service) handleDiscard(w http.ResponseWriter, r *http.Request) error {
	claims, _ := authn.ClaimsFrom(r.Context())

	var req mtproto.DiscardCall
	if err := httpx.DecodeJSON(r, 16<<10, &req); err != nil {
		return err
	}

	state, err := s.loadCall(r.Context(), req.CallID)
	if err != nil {
		// Already gone. Discarding a call that has ended is not an error —
		// both sides send it, and one of them is always second.
		httpx.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
		return nil
	}

	var peer int64
	switch claims.UserID {
	case state.CallerID:
		peer = state.CalleeID
	case state.CalleeID:
		peer = state.CallerID
	default:
		return httpx.ErrForbidden("you are not a party to this call")
	}

	s.releaseCall(r.Context(), state.CallerID, state.CalleeID)
	if err := s.redis.Raw().Del(r.Context(), callKey(state.ID)).Err(); err != nil {
		s.redis.Raw().Del(r.Context(), callKey(state.ID))
	}

	s.notify(r.Context(), peer, mtproto.CallStateUpdate{
		CallID: state.ID, State: mtproto.CallStateEnded,
		PeerID: claims.UserID, Reason: req.Reason,
	})

	httpx.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
	return nil
}

func (s *service) handleTURNCredentials(w http.ResponseWriter, r *http.Request) error {
	claims, _ := authn.ClaimsFrom(r.Context())

	if s.turn == nil {
		return httpx.ErrUnavailable("no TURN relay is configured")
	}

	creds := s.turn.Issue(claims.UserID)
	httpx.WriteJSON(w, http.StatusOK, creds)
	return nil
}

// ---------------------------------------------------------------------------
// state
// ---------------------------------------------------------------------------

func (s *service) saveCall(ctx context.Context, state callState) error {
	body, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return s.redis.Raw().Set(ctx, callKey(state.ID), body, callTTL).Err()
}

func (s *service) loadCall(ctx context.Context, id int64) (callState, error) {
	raw, err := s.redis.Raw().Get(ctx, callKey(id)).Bytes()
	if err != nil {
		return callState{}, err
	}
	var state callState
	if err := json.Unmarshal(raw, &state); err != nil {
		return callState{}, err
	}
	return state, nil
}

// releaseCall frees both participants' single-call slots.
func (s *service) releaseCall(ctx context.Context, a, b int64) {
	s.redis.Raw().Del(ctx, activeCallKey(a), activeCallKey(b))
}

func (s *service) notify(ctx context.Context, userID int64, update mtproto.CallStateUpdate) {
	payload, err := json.Marshal(update)
	if err != nil {
		return
	}
	if err := s.bus.Publish(ctx, redisx.ChannelUser(userID), redisx.Update{
		Kind: "call_state", UserID: userID, Body: payload,
	}); err != nil {
		// Best effort. A missed ring is recovered by the caller's timeout,
		// and failing the request would leave the call state inconsistent.
		_ = err
	}
}
