package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pervagans/messaging-app/pkg/events"
	"github.com/pervagans/messaging-app/pkg/mtproto"
	"github.com/pervagans/messaging-app/pkg/mtproto/transport"
	"github.com/pervagans/messaging-app/pkg/ratelimit"
	"github.com/pervagans/messaging-app/pkg/redisx"
	"github.com/pervagans/messaging-app/pkg/telemetry"
)

// Session is one client connection's MTProto state.
//
// The lifecycle has three phases and the code below follows them in order:
//
//	unauthenticated → auth key negotiated → identity bound
//
// A connection can send exactly one class of message in each phase. Enforcing
// that with an explicit state, rather than by checking flags inside each
// handler, is what makes it impossible to reach a privileged RPC by sending
// the right constructor at the wrong time.
type Session struct {
	g    *Gateway
	conn transport.Conn
	log  *slog.Logger

	// Phase 1: handshake.
	handshake *mtproto.ServerHandshake

	// Phase 2: encrypted transport.
	authKey   *mtproto.AuthKey
	sessionID int64
	salt      atomic.Int64
	msgIDs    mtproto.MsgIDGenerator
	seqNo     mtproto.SeqNoCounter
	validator *mtproto.MsgIDValidator

	// Phase 3: bound identity.
	userID   atomic.Int64
	deviceID atomic.Int64

	// out carries updates to the writer goroutine.
	out chan redisx.Update
	// pendingAcks collects msg_ids to acknowledge on the next flush.
	ackMu       sync.Mutex
	pendingAcks []int64

	channels map[string]struct{}
	chanMu   sync.Mutex

	closeOnce sync.Once
	closed    atomic.Bool
	writeMu   sync.Mutex
}

// NewSession builds a session for a connection.
func NewSession(g *Gateway, conn transport.Conn) *Session {
	return &Session{
		g:         g,
		conn:      conn,
		log:       g.Log.With("remote", conn.RemoteAddr().String(), "transport", string(conn.Kind())),
		handshake: mtproto.NewServerHandshake(g.ServerKey, g.Cfg.HandshakeTimeout),
		validator: mtproto.NewMsgIDValidator(),
		out:       make(chan redisx.Update, g.Cfg.UpdateQueueSize),
		channels:  make(map[string]struct{}, 2),
	}
}

// Run drives the read loop until the connection ends.
func (s *Session) Run(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); s.writeLoop(ctx) }()

	// Presence heartbeats keep the Redis TTL alive for as long as this
	// connection lives. They stop the moment the loop exits, which is what
	// makes presence self-healing when a pod dies without cleanup.
	wg.Add(1)
	go func() { defer wg.Done(); s.heartbeatLoop(ctx) }()

	defer wg.Wait()
	defer cancel()

	for {
		frame, err := s.conn.ReadFrame(ctx)
		if err != nil {
			switch {
			case errors.Is(err, transport.ErrClosed), errors.Is(err, context.Canceled):
			case errors.Is(err, transport.ErrTimeout):
				s.log.Debug("connection idle, closing")
			default:
				s.log.Debug("read failed", "error", err)
			}
			return
		}
		if err := s.handleFrame(ctx, frame); err != nil {
			s.log.Info("closing connection", "reason", err)
			return
		}
	}
}

// handleFrame routes one wire frame.
func (s *Session) handleFrame(ctx context.Context, frame []byte) error {
	authKeyID, err := mtproto.PeekAuthKeyID(frame)
	if err != nil {
		return fmt.Errorf("unreadable frame: %w", err)
	}

	if authKeyID == 0 {
		// Plain messages are only ever legal during the handshake. Accepting
		// them afterwards would let anyone bypass encryption by zeroing the
		// key id.
		if s.authKey != nil {
			return errors.New("plain message received on an encrypted session")
		}
		return s.handlePlain(ctx, frame)
	}

	if s.authKey == nil {
		// The client claims a key we have not negotiated on this connection —
		// normal after a reconnect. Resolve it from the shared session store.
		key, err := s.g.Sessions.Load(ctx, authKeyID)
		if err != nil {
			s.log.Info("unknown auth key", "auth_key_id", mtproto.AuthKeyIDHex(authKeyID))
			// Say nothing useful: a probe must not learn which key ids exist.
			return errors.New("unknown auth key")
		}
		s.authKey = key
		if bound, err := s.g.Sessions.LoadBinding(ctx, authKeyID); err == nil {
			s.userID.Store(bound.UserID)
			s.deviceID.Store(bound.DeviceID)
			if err := s.attachIdentity(ctx, bound.UserID, bound.DeviceID); err != nil {
				s.log.Warn("could not restore the session binding", "error", err)
			}
		}
	}

	msg, err := mtproto.Decrypt(s.authKey, frame, mtproto.ClientToServer)
	if err != nil {
		// A decryption failure is either corruption or an attack. Either way
		// the connection is unusable: the stream position is unknown.
		return fmt.Errorf("decrypt: %w", err)
	}

	if err := s.checkEnvelope(ctx, msg); err != nil {
		return nil // a bad_msg_notification has already been sent
	}

	if s.sessionID == 0 {
		s.sessionID = msg.SessionID
		s.msgIDs.AdoptPeerTime(msg.MsgID)
	} else if msg.SessionID != s.sessionID {
		// A new session id on the same auth key means the client restarted.
		// Tell it so, and reset our own counters.
		s.sessionID = msg.SessionID
		s.seqNo = mtproto.SeqNoCounter{}
		salt := s.salt.Load()
		s.sendService(ctx, mtproto.CNewSessionReset, mtproto.NewSessionCreated{
			FirstMsgID: msg.MsgID, UniqueID: msg.SessionID, ServerSalt: salt,
		})
	}

	// Content-related messages must be acknowledged so the client stops
	// retransmitting them.
	if msg.IsContentRelated() {
		s.queueAck(msg.MsgID)
	}

	return s.dispatch(ctx, msg)
}

// checkEnvelope validates msg_id and salt, answering with the specific
// correction the client needs rather than just dropping the message.
func (s *Session) checkEnvelope(ctx context.Context, msg *mtproto.Message) error {
	if err := s.validator.Check(msg.MsgID); err != nil {
		code := mtproto.BadMsgIDTooLow
		switch {
		case errors.Is(err, mtproto.ErrMsgIDTooNew):
			code = mtproto.BadMsgIDTooHigh
		case errors.Is(err, mtproto.ErrMsgIDReplay):
			code = mtproto.BadMsgIDDuplicate
		case errors.Is(err, mtproto.ErrMsgIDParity):
			code = mtproto.BadMsgIDEvenOdd
		}
		s.sendService(ctx, mtproto.CBadMsgNotify, mtproto.BadMsgNotification{
			BadMsgID: msg.MsgID, BadSeqNo: msg.SeqNo, ErrorCode: code,
		})
		return err
	}

	if current := s.salt.Load(); current != 0 && msg.Salt != current {
		// A stale salt after an hourly rotation is expected. Hand the client
		// the current one so it recovers in a single round trip instead of
		// re-authenticating.
		s.sendService(ctx, mtproto.CBadServerSalt, mtproto.BadServerSalt{
			BadMsgID: msg.MsgID, BadSeqNo: msg.SeqNo,
			ErrorCode: mtproto.BadSaltInvalid, NewSalt: current,
		})
		return mtproto.ErrBadSalt
	}
	return nil
}

// ---------------------------------------------------------------------------
// Handshake
// ---------------------------------------------------------------------------

func (s *Session) handlePlain(ctx context.Context, frame []byte) error {
	msgID, payload, err := mtproto.DecodePlain(frame)
	if err != nil {
		return fmt.Errorf("malformed plain message: %w", err)
	}
	_ = msgID

	constructor, err := mtproto.PeekConstructor(payload)
	if err != nil {
		return err
	}

	ip := hostOf(s.conn.RemoteAddr())
	if d, err := s.g.Limiter.Allow(ctx,
		ratelimit.KeyIP("handshake", ip), ratelimit.HandshakePerIP); err == nil && !d.Allowed {
		return fmt.Errorf("handshake rate limited for %s", ip)
	}

	switch constructor {
	case mtproto.CReqPQ:
		var req mtproto.ReqPQ
		if err := mtproto.Decode(payload, &req); err != nil {
			return err
		}
		res, err := s.handshake.ReqPQ(req.Nonce)
		if err != nil {
			return err
		}
		return s.sendPlain(ctx, mtproto.CResPQ, res)

	case mtproto.CReqDHParams:
		var req mtproto.ReqDHParams
		if err := mtproto.Decode(payload, &req); err != nil {
			return err
		}
		res, err := s.handshake.ReqDHParams(req)
		if err != nil {
			s.log.Info("handshake step 3 rejected", "error", err)
			// A generic code: telling the client *why* would turn the server
			// into an oracle for forged handshakes.
			_ = s.sendPlain(ctx, mtproto.CHandshakeError, mtproto.HandshakeError{Code: "DH_PARAMS_INVALID"})
			return err
		}
		return s.sendPlain(ctx, mtproto.CServerDHParams, res)

	case mtproto.CSetClientDHParams:
		var req mtproto.SetClientDHParams
		if err := mtproto.Decode(payload, &req); err != nil {
			return err
		}
		key, ok, err := s.handshake.SetClientDHParams(req)
		if err != nil {
			s.log.Info("handshake step 5 rejected", "error", err)
			_ = s.sendPlain(ctx, mtproto.CHandshakeError, mtproto.HandshakeError{Code: "DH_GEN_FAILED"})
			return err
		}

		// Persist the key before confirming: if we confirmed first and then
		// failed to store it, the client would believe it holds a valid
		// session that no pod can resolve.
		if err := s.g.Sessions.Save(ctx, key); err != nil {
			_ = s.sendPlain(ctx, mtproto.CHandshakeError, mtproto.HandshakeError{Code: "SESSION_STORE_FAILED"})
			return fmt.Errorf("persist auth key: %w", err)
		}

		s.authKey = key
		salt, err := mtproto.NewSalt()
		if err != nil {
			return err
		}
		s.salt.Store(salt)

		s.log.Info("auth key negotiated", "auth_key_id", key.IDHex())
		return s.sendPlain(ctx, mtproto.CDHGenOK, ok)
	}

	return fmt.Errorf("constructor %#x is not valid before authentication", uint32(constructor))
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

func (s *Session) sendPlain(ctx context.Context, id mtproto.ConstructorID, v any) error {
	payload, err := mtproto.Encode(id, v)
	if err != nil {
		return err
	}
	frame := mtproto.EncodePlain(s.msgIDs.Next(mtproto.KindFromServerResponse), payload)

	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.conn.WriteFrame(ctx, frame)
}

// sendEncrypted writes one encrypted message.
func (s *Session) sendEncrypted(ctx context.Context, id mtproto.ConstructorID, v any, contentRelated bool) error {
	if s.authKey == nil {
		return errors.New("session: not yet encrypted")
	}
	payload, err := mtproto.Encode(id, v)
	if err != nil {
		return err
	}

	kind := mtproto.KindFromServerPush
	if contentRelated {
		kind = mtproto.KindFromServerResponse
	}

	msg := &mtproto.Message{
		Salt:      s.salt.Load(),
		SessionID: s.sessionID,
		MsgID:     s.msgIDs.Next(kind),
		SeqNo:     s.seqNo.Next(contentRelated),
		Body:      payload,
	}
	frame, err := mtproto.Encrypt(s.authKey, msg, mtproto.ServerToClient)
	if err != nil {
		return err
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.conn.WriteFrame(ctx, frame)
}

// sendService writes a non-content message, logging rather than failing:
// a service message the client missed is recoverable, and tearing down the
// connection over one would be worse than the problem.
func (s *Session) sendService(ctx context.Context, id mtproto.ConstructorID, v any) {
	if err := s.sendEncrypted(ctx, id, v, false); err != nil {
		s.log.Debug("service message not delivered", "constructor", fmt.Sprintf("%#x", uint32(id)), "error", err)
	}
}

func (s *Session) queueAck(msgID int64) {
	s.ackMu.Lock()
	s.pendingAcks = append(s.pendingAcks, msgID)
	s.ackMu.Unlock()
}

func (s *Session) flushAcks(ctx context.Context) {
	s.ackMu.Lock()
	if len(s.pendingAcks) == 0 {
		s.ackMu.Unlock()
		return
	}
	acks := s.pendingAcks
	s.pendingAcks = nil
	s.ackMu.Unlock()

	s.sendService(ctx, mtproto.CMsgsAck, mtproto.MsgsAck{MsgIDs: acks})
}

// Enqueue offers an update to this session's writer.
//
// It never blocks. A client that cannot keep up loses updates and resyncs
// with getDifference on its next reconnect; blocking here would stall the
// pod's single dispatch goroutine and punish every other user on the pod for
// one slow phone.
func (s *Session) Enqueue(u redisx.Update) {
	if s.closed.Load() {
		return
	}
	select {
	case s.out <- u:
	default:
		telemetry.MessagesDelivered.WithLabelValues("dropped").Inc()
		s.log.Warn("update dropped: client is not keeping up",
			"user_id", s.userID.Load(), "kind", u.Kind)
	}
}

// writeLoop serialises everything written to the connection.
func (s *Session) writeLoop(ctx context.Context) {
	// Acks are batched: a client sending twenty messages a second should get
	// one ack frame, not twenty.
	ackTicker := time.NewTicker(200 * time.Millisecond)
	defer ackTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-ackTicker.C:
			s.flushAcks(ctx)

		case u, ok := <-s.out:
			if !ok {
				return
			}
			if err := s.sendUpdate(ctx, u); err != nil {
				s.log.Debug("update not delivered", "error", err)
				return
			}
		}
	}
}

func (s *Session) sendUpdate(ctx context.Context, u redisx.Update) error {
	if s.authKey == nil {
		return nil // nothing to encrypt with yet
	}

	var payload any
	if len(u.Body) > 0 {
		var decoded any
		if err := json.Unmarshal(u.Body, &decoded); err == nil {
			payload = decoded
		}
	}

	update := mtproto.Update{
		Kind: string(u.Kind), ChatID: u.ChatID, Seq: u.Seq,
		UserID: u.UserID, Date: u.At, Payload: payload,
	}
	if err := s.sendEncrypted(ctx, mtproto.CUpdate, update, true); err != nil {
		return err
	}
	telemetry.MessagesDelivered.WithLabelValues("realtime").Inc()
	return nil
}

// heartbeatLoop refreshes presence and rotates the server salt.
func (s *Session) heartbeatLoop(ctx context.Context) {
	presenceTick := time.NewTicker(s.g.Cfg.PingInterval / 2)
	defer presenceTick.Stop()
	saltTick := time.NewTicker(s.g.Cfg.SaltRotation)
	defer saltTick.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-presenceTick.C:
			userID, deviceID := s.userID.Load(), s.deviceID.Load()
			if userID == 0 {
				continue
			}
			if err := s.g.Presence.Heartbeat(ctx, userID, deviceID); err != nil {
				s.log.Warn("presence heartbeat failed", "error", err)
			}

		case <-saltTick.C:
			salt, err := mtproto.NewSalt()
			if err != nil {
				continue
			}
			s.salt.Store(salt)
			// Push the new salt proactively so the client does not have to
			// discover the rotation by having a message rejected.
			s.sendService(ctx, mtproto.CBadServerSalt, mtproto.BadServerSalt{NewSalt: salt})
		}
	}
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

// attachIdentity subscribes the session to its user's update channel and
// records presence.
func (s *Session) attachIdentity(ctx context.Context, userID, deviceID int64) error {
	channel := redisx.ChannelUser(userID)

	s.chanMu.Lock()
	_, already := s.channels[channel]
	if !already {
		s.channels[channel] = struct{}{}
	}
	s.chanMu.Unlock()

	if !already {
		if err := s.g.subscribe(ctx, channel, s); err != nil {
			s.chanMu.Lock()
			delete(s.channels, channel)
			s.chanMu.Unlock()
			return fmt.Errorf("subscribe to %s: %w", channel, err)
		}
	}

	if err := s.g.Presence.Online(ctx, userID, redisx.DeviceRoute{
		DeviceID: deviceID,
		Pod:      s.g.Cfg.PodName,
		Region:   s.g.Cfg.Base.Region,
		Platform: string(s.conn.Kind()),
	}); err != nil {
		// Presence is advisory. Failing the bind over it would deny a user
		// their session because a cache was briefly unavailable.
		s.log.Warn("could not record presence", "error", err)
	}

	s.publishPresence(ctx, userID, deviceID, events.PresenceOnline)
	return nil
}

func (s *Session) publishPresence(ctx context.Context, userID, deviceID int64, state events.PresenceState) {
	evt := events.PresenceEvent{
		V: events.CurrentVersion, UserID: userID, DeviceID: deviceID,
		State: state, At: time.Now().UTC(),
	}
	body, err := json.Marshal(evt)
	if err != nil {
		return
	}
	detached := context.WithoutCancel(ctx)
	go func() {
		bg, cancel := context.WithTimeout(detached, 5*time.Second)
		defer cancel()
		if err := s.g.Producer.Publish(bg, events.TopicPresenceEvents,
			[]byte(fmt.Sprint(userID)), body); err != nil {
			s.log.Debug("presence event not published", "error", err)
		}
	}()
}

// Close tears the session down.
func (s *Session) Close() {
	s.closeOnce.Do(func() {
		s.closed.Store(true)

		// A fresh context: the request context is already cancelled by the
		// time we get here, and unsubscribing is exactly the work that must
		// still happen.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		s.chanMu.Lock()
		channels := make([]string, 0, len(s.channels))
		for c := range s.channels {
			channels = append(channels, c)
		}
		s.channels = nil
		s.chanMu.Unlock()

		for _, c := range channels {
			s.g.unsubscribe(ctx, c, s)
		}

		if userID := s.userID.Load(); userID != 0 {
			deviceID := s.deviceID.Load()
			if err := s.g.Presence.Offline(ctx, userID, deviceID); err != nil {
				s.log.Warn("could not clear presence", "error", err)
			}
			s.publishPresence(ctx, userID, deviceID, events.PresenceOffline)
		}

		close(s.out)
		_ = s.conn.Close()
	})
}

// hostOf extracts the address without the port, for rate-limit keys.
func hostOf(a net.Addr) string {
	if a == nil {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String()
	}
	return host
}
