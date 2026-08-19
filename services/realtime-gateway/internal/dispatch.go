package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/pervagans/messaging-app/pkg/mtproto"
	"github.com/pervagans/messaging-app/pkg/telemetry"
)

// dispatch routes a decrypted message to its handler.
//
// Every branch except ping, ack and auth.bind requires a bound identity. That
// check happens once, here, rather than at the top of each handler — one place
// to get right instead of a dozen.
func (s *Session) dispatch(ctx context.Context, msg *mtproto.Message) error {
	constructor, err := mtproto.PeekConstructor(msg.Body)
	if err != nil {
		return nil // an unreadable payload is not worth dropping the connection
	}

	started := time.Now()
	name := constructorName(constructor)

	switch constructor {
	case mtproto.CPing:
		s.handlePing(ctx, msg)

	case mtproto.CMsgsAck:
		// Nothing to do: this server does not retransmit unacknowledged
		// messages, because every update it sends is also recoverable through
		// getDifference. Acks are accepted so clients that send them are not
		// surprised by an error.

	case mtproto.CDestroySession:
		s.handleDestroySession(ctx, msg)

	case mtproto.CMsgContainer:
		return s.handleContainer(ctx, msg)

	case mtproto.CAuthBind:
		s.handleAuthBind(ctx, msg)

	default:
		if s.userID.Load() == 0 {
			s.rpcError(ctx, msg.MsgID, 401, "AUTH_KEY_UNBOUND")
			telemetry.ObserveRPC("mtproto", name, "401", started)
			return nil
		}
		s.handleAPI(ctx, msg, constructor)
	}

	telemetry.ObserveRPC("mtproto", name, "ok", started)
	return nil
}

// handleContainer unpacks a batched frame.
//
// Clients batch their pending acks, a ping and a catch-up call into one
// message after waking from sleep. Nesting is refused: a container inside a
// container would let a client build an amplification bomb out of one frame.
func (s *Session) handleContainer(ctx context.Context, msg *mtproto.Message) error {
	var container mtproto.MsgContainer
	if err := mtproto.Decode(msg.Body, &container); err != nil {
		return nil
	}
	const maxContained = 64
	if len(container.Messages) > maxContained {
		s.rpcError(ctx, msg.MsgID, 400, "CONTAINER_TOO_LARGE")
		return nil
	}

	for _, inner := range container.Messages {
		constructor, err := mtproto.PeekConstructor(inner.Payload)
		if err != nil || constructor == mtproto.CMsgContainer {
			continue
		}
		sub := &mtproto.Message{
			Salt: msg.Salt, SessionID: msg.SessionID,
			MsgID: inner.MsgID, SeqNo: inner.SeqNo, Body: inner.Payload,
		}
		if sub.IsContentRelated() {
			s.queueAck(sub.MsgID)
		}
		if err := s.dispatch(ctx, sub); err != nil {
			return err
		}
	}
	return nil
}

func (s *Session) handlePing(ctx context.Context, msg *mtproto.Message) {
	var ping mtproto.Ping
	_ = mtproto.Decode(msg.Body, &ping)

	if ping.DisconnectAfter > 0 {
		// The client is telling us it is going to sleep and how long to keep
		// the connection before reclaiming it.
		s.conn.SetIdleTimeout(time.Duration(ping.DisconnectAfter) * time.Second)
	}

	s.sendService(ctx, mtproto.CPong, mtproto.Pong{
		MsgID: msg.MsgID, PingID: ping.PingID, ServerTime: time.Now().Unix(),
	})
}

func (s *Session) handleDestroySession(ctx context.Context, msg *mtproto.Message) {
	if s.authKey != nil {
		if err := s.g.Sessions.Delete(ctx, s.authKey.ID()); err != nil {
			s.log.Warn("could not delete the session", "error", err)
		}
		// Wipe the key material now rather than waiting for the GC, so a heap
		// dump taken after a logout does not contain a usable key.
		s.authKey.Zero()
	}
	s.sendService(ctx, mtproto.COK, mtproto.OK{OK: true})
	_ = msg
}

// handleAuthBind attaches an authenticated identity to the auth key.
func (s *Session) handleAuthBind(ctx context.Context, msg *mtproto.Message) {
	var req mtproto.AuthBind
	if err := mtproto.Decode(msg.Body, &req); err != nil {
		s.rpcError(ctx, msg.MsgID, 400, "BAD_REQUEST")
		return
	}
	if s.authKey == nil {
		s.rpcError(ctx, msg.MsgID, 401, "AUTH_KEY_MISSING")
		return
	}

	resolved, err := s.g.Upstream.ResolveToken(ctx, ResolveTokenRequest{
		AccessToken: req.AccessToken,
		AuthKeyID:   s.authKey.IDHex(),
		Platform:    orDefault(req.Platform, string(s.conn.Kind())),
		AppVersion:  req.AppVersion,
		DeviceModel: req.DeviceModel,
		IP:          hostOf(s.conn.RemoteAddr()),
	})
	if err != nil {
		var ue *UpstreamError
		if errors.As(err, &ue) && ue.Status == 401 {
			s.rpcError(ctx, msg.MsgID, 401, "AUTH_TOKEN_INVALID")
			return
		}
		s.log.Warn("token resolution failed", "error", err)
		s.rpcError(ctx, msg.MsgID, 503, "AUTH_UNAVAILABLE")
		return
	}

	s.userID.Store(resolved.UserID)
	s.deviceID.Store(resolved.DeviceID)

	// Remember the binding so a reconnect that presents the same auth key
	// resumes without another round trip to the auth service.
	if err := s.g.Sessions.SaveBinding(ctx, s.authKey.ID(), Binding{
		UserID: resolved.UserID, DeviceID: resolved.DeviceID,
	}); err != nil {
		s.log.Warn("could not persist the session binding", "error", err)
	}

	if err := s.attachIdentity(ctx, resolved.UserID, resolved.DeviceID); err != nil {
		s.log.Error("could not attach the identity", "error", err)
		s.rpcError(ctx, msg.MsgID, 503, "SUBSCRIBE_FAILED")
		return
	}

	salt := s.salt.Load()
	if salt == 0 {
		if newSalt, err := mtproto.NewSalt(); err == nil {
			salt = newSalt
			s.salt.Store(salt)
		}
	}

	s.log.Info("session bound", "user_id", resolved.UserID, "device_id", resolved.DeviceID)

	s.rpcResult(ctx, msg.MsgID, mtproto.AuthBindResult{
		UserID: resolved.UserID, DeviceID: resolved.DeviceID,
		ServerSalt: salt, SessionID: s.sessionID, ServerTime: time.Now().Unix(),
	})
}

// handleAPI forwards a client call to the owning service.
//
// The gateway holds no business logic on purpose: it is the tier that must
// scale with *connections*, and mixing in logic that scales with *requests*
// would couple two very different capacity curves.
func (s *Session) handleAPI(ctx context.Context, msg *mtproto.Message, constructor mtproto.ConstructorID) {
	userID, deviceID := s.userID.Load(), s.deviceID.Load()

	switch constructor {
	case mtproto.CSendMessage:
		var req mtproto.SendMessage
		if err := mtproto.Decode(msg.Body, &req); err != nil {
			s.rpcError(ctx, msg.MsgID, 400, "BAD_REQUEST")
			return
		}
		res, err := s.g.Upstream.SendMessage(ctx, userID, deviceID, req)
		s.reply(ctx, msg.MsgID, res, err)

	case mtproto.CGetHistory:
		var req mtproto.GetHistory
		if err := mtproto.Decode(msg.Body, &req); err != nil {
			s.rpcError(ctx, msg.MsgID, 400, "BAD_REQUEST")
			return
		}
		res, err := s.g.Upstream.GetHistory(ctx, userID, deviceID, req)
		s.reply(ctx, msg.MsgID, res, err)

	case mtproto.CGetDifference:
		var req mtproto.GetDifference
		if err := mtproto.Decode(msg.Body, &req); err != nil {
			s.rpcError(ctx, msg.MsgID, 400, "BAD_REQUEST")
			return
		}
		res, err := s.g.Upstream.GetDifference(ctx, userID, deviceID, req)
		s.reply(ctx, msg.MsgID, res, err)

	case mtproto.CReadHistory:
		var req mtproto.ReadHistory
		if err := mtproto.Decode(msg.Body, &req); err != nil {
			s.rpcError(ctx, msg.MsgID, 400, "BAD_REQUEST")
			return
		}
		res, err := s.g.Upstream.ReadHistory(ctx, userID, deviceID, req)
		s.reply(ctx, msg.MsgID, res, err)

	case mtproto.CGetDialogs:
		var req mtproto.GetDialogs
		if err := mtproto.Decode(msg.Body, &req); err != nil {
			s.rpcError(ctx, msg.MsgID, 400, "BAD_REQUEST")
			return
		}
		res, err := s.g.Upstream.GetDialogs(ctx, userID, deviceID, req)
		s.reply(ctx, msg.MsgID, res, err)

	case mtproto.CSetTyping:
		var req mtproto.SetTyping
		if err := mtproto.Decode(msg.Body, &req); err != nil {
			s.rpcError(ctx, msg.MsgID, 400, "BAD_REQUEST")
			return
		}
		// Typing is fire-and-forget: the client does not wait for it, and a
		// failed indicator is not worth a round trip to report.
		detached := context.WithoutCancel(ctx)
		go func() {
			bg, cancel := context.WithTimeout(detached, 3*time.Second)
			defer cancel()
			if err := s.g.Upstream.SetTyping(bg, userID, deviceID, req); err != nil {
				s.log.Debug("typing indicator not delivered", "error", err)
			}
		}()
		s.rpcResult(ctx, msg.MsgID, mtproto.OK{OK: true})

	default:
		s.rpcError(ctx, msg.MsgID, 400, "METHOD_NOT_FOUND")
	}
}

// reply turns an upstream result or error into the right MTProto response.
func (s *Session) reply(ctx context.Context, reqMsgID int64, result any, err error) {
	if err == nil {
		s.rpcResult(ctx, reqMsgID, result)
		return
	}

	var ue *UpstreamError
	if errors.As(err, &ue) {
		// Preserve flood-wait semantics: the client parses the seconds out of
		// the message and backs off by exactly that much.
		if ue.Status == 429 && ue.RetryAfter > 0 {
			e := mtproto.FloodWait(ue.RetryAfter)
			s.rpcErrorMsg(ctx, reqMsgID, e.Code, e.Message)
			return
		}
		s.rpcError(ctx, reqMsgID, int32(ue.Status), ue.Code)
		return
	}

	s.log.Warn("upstream call failed", "error", err)
	s.rpcError(ctx, reqMsgID, 503, "INTERNAL")
}

func (s *Session) rpcResult(ctx context.Context, reqMsgID int64, result any) {
	body, err := json.Marshal(result)
	if err != nil {
		s.rpcError(ctx, reqMsgID, 500, "ENCODE_FAILED")
		return
	}
	if err := s.sendEncrypted(ctx, mtproto.CRPCResult, mtproto.RPCResult{
		ReqMsgID: reqMsgID, Result: body,
	}, true); err != nil {
		s.log.Debug("rpc result not delivered", "error", err)
	}
}

func (s *Session) rpcError(ctx context.Context, reqMsgID int64, code int32, message string) {
	s.rpcErrorMsg(ctx, reqMsgID, code, message)
}

func (s *Session) rpcErrorMsg(ctx context.Context, reqMsgID int64, code int32, message string) {
	if err := s.sendEncrypted(ctx, mtproto.CRPCError, mtproto.RPCError{
		ReqMsgID: reqMsgID, Code: code, Message: message,
	}, true); err != nil {
		s.log.Debug("rpc error not delivered", "error", err)
	}
}

// constructorName renders a constructor for metrics labels. Unknown values
// collapse to "unknown" so a client sending random ids cannot create unbounded
// metric cardinality.
func constructorName(id mtproto.ConstructorID) string {
	switch id {
	case mtproto.CPing:
		return "ping"
	case mtproto.CMsgsAck:
		return "msgs_ack"
	case mtproto.CAuthBind:
		return "auth.bind"
	case mtproto.CSendMessage:
		return "messages.send"
	case mtproto.CGetHistory:
		return "messages.getHistory"
	case mtproto.CGetDifference:
		return "updates.getDifference"
	case mtproto.CReadHistory:
		return "messages.readHistory"
	case mtproto.CSetTyping:
		return "messages.setTyping"
	case mtproto.CGetDialogs:
		return "messages.getDialogs"
	case mtproto.CDestroySession:
		return "destroy_session"
	case mtproto.CMsgContainer:
		return "msg_container"
	}
	return "unknown"
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}
