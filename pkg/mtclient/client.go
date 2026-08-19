// Package mtclient is a complete MTProto client.
//
// It exists for three reasons, in order of importance:
//
//  1. It makes the protocol testable end to end. A test that drives this
//     client against a real gateway over a real socket proves the handshake,
//     the framing, the obfuscation, the envelope and the dispatch all compose
//     — which no amount of unit testing each layer separately does.
//  2. It is what the load generator drives.
//  3. It is the reference the Kotlin and TypeScript clients are written
//     against: when a mobile client misbehaves, this is the thing to compare
//     it to.
package mtclient

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pervagans/messaging-app/pkg/mtproto"
	"github.com/pervagans/messaging-app/pkg/mtproto/codec"
)

// Options configures a client.
type Options struct {
	// Addr is host:port of the gateway's TCP listener.
	Addr string
	// ServerPublicKeyPEM is the pinned server key.
	//
	// Pinning is not optional in any real deployment. The handshake protects
	// against a passive observer; only the pin protects against an active
	// attacker, who would otherwise substitute their own key, learn new_nonce
	// and read the whole Diffie-Hellman exchange.
	ServerPublicKeyPEM string
	// Framing is abridged, intermediate or padded.
	Framing string
	// Obfuscated wraps the connection in obfuscation2.
	Obfuscated bool
	// DialTimeout bounds connection establishment.
	DialTimeout time.Duration
	// RequestTimeout bounds one RPC.
	RequestTimeout time.Duration
	// OnUpdate receives server-pushed updates.
	OnUpdate func(mtproto.Update)
}

// Client is one connection to the gateway.
type Client struct {
	opts Options

	conn net.Conn
	br   *bufio.Reader
	fr   codec.Codec

	authKey   *mtproto.AuthKey
	sessionID int64
	salt      atomic.Int64
	msgIDs    mtproto.MsgIDGenerator
	seqNo     mtproto.SeqNoCounter

	userID   atomic.Int64
	deviceID atomic.Int64

	// pending maps a request msg_id to the channel waiting for its answer.
	mu      sync.Mutex
	pending map[int64]chan result

	writeMu sync.Mutex
	closed  atomic.Bool
	done    chan struct{}
	readErr atomic.Pointer[error]
}

type result struct {
	body json.RawMessage
	err  error
}

// Dial connects, runs the handshake and starts the read loop.
func Dial(ctx context.Context, o Options) (*Client, error) {
	if o.DialTimeout == 0 {
		// The window covers the TCP connect *and* the full handshake, which
		// costs a 2048-bit modular exponentiation on each side plus the
		// proof-of-work factorisation. Ten seconds is enough on real hardware
		// but leaves nothing for a slow phone on a bad network, and none for
		// an instrumented build.
		o.DialTimeout = 20 * time.Second
	}
	if o.RequestTimeout == 0 {
		o.RequestTimeout = 30 * time.Second
	}
	if o.Framing == "" {
		o.Framing = "intermediate"
	}

	d := net.Dialer{Timeout: o.DialTimeout}
	raw, err := d.DialContext(ctx, "tcp", o.Addr)
	if err != nil {
		return nil, fmt.Errorf("mtclient: dial %s: %w", o.Addr, err)
	}
	if tc, ok := raw.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}

	framing, err := codec.ByName(o.Framing)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}

	c := &Client{
		opts:    o,
		pending: make(map[int64]chan result),
		done:    make(chan struct{}),
	}

	if o.Obfuscated {
		oc, err := codec.DialObfuscated(raw, framing, 1)
		if err != nil {
			_ = raw.Close()
			return nil, err
		}
		c.conn = oc
		c.fr = oc.Codec
	} else {
		if err := codec.WriteMagic(raw, framing); err != nil {
			_ = raw.Close()
			return nil, err
		}
		c.conn = raw
		c.fr = framing
	}
	c.br = bufio.NewReaderSize(c.conn, 32<<10)

	if err := c.handshake(ctx); err != nil {
		_ = c.conn.Close()
		return nil, err
	}

	sessionID, err := randomInt64()
	if err != nil {
		_ = c.conn.Close()
		return nil, err
	}
	c.sessionID = sessionID

	go c.readLoop()
	return c, nil
}

// handshake runs the five-message auth-key negotiation.
func (c *Client) handshake(ctx context.Context) error {
	h, err := mtproto.NewClientHandshake(c.opts.ServerPublicKeyPEM)
	if err != nil {
		return err
	}

	deadline := time.Now().Add(c.opts.DialTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = c.conn.SetDeadline(deadline)
	defer func() { _ = c.conn.SetDeadline(time.Time{}) }()

	// 1 → req_pq
	reqPQ, err := h.Start()
	if err != nil {
		return err
	}
	if err := c.writePlain(mtproto.CReqPQ, reqPQ); err != nil {
		return err
	}

	// 2 ← res_pq
	var resPQ mtproto.ResPQ
	if err := c.readPlainInto(mtproto.CResPQ, &resPQ); err != nil {
		return err
	}

	// 3 → req_dh_params (this is where the proof-of-work factorisation happens)
	reqDH, err := h.OnResPQ(resPQ)
	if err != nil {
		return err
	}
	if err := c.writePlain(mtproto.CReqDHParams, reqDH); err != nil {
		return err
	}

	// 4 ← server_dh_params
	var serverDH mtproto.ServerDHParams
	if err := c.readPlainInto(mtproto.CServerDHParams, &serverDH); err != nil {
		return err
	}

	// 5 → set_client_dh_params
	setDH, err := h.OnServerDHParams(serverDH)
	if err != nil {
		return err
	}
	if err := c.writePlain(mtproto.CSetClientDHParams, setDH); err != nil {
		return err
	}

	// 6 ← dh_gen_ok
	var genOK mtproto.DHGenOK
	if err := c.readPlainInto(mtproto.CDHGenOK, &genOK); err != nil {
		return err
	}

	key, err := h.OnDHGenOK(genOK)
	if err != nil {
		return err
	}
	c.authKey = key
	return nil
}

func (c *Client) writePlain(id mtproto.ConstructorID, v any) error {
	payload, err := mtproto.Encode(id, v)
	if err != nil {
		return err
	}
	frame := mtproto.EncodePlain(c.msgIDs.Next(mtproto.KindFromClient), payload)
	return c.fr.WriteFrame(c.conn, frame)
}

func (c *Client) readPlainInto(want mtproto.ConstructorID, v any) error {
	frame, err := c.fr.ReadFrame(c.br)
	if err != nil {
		return fmt.Errorf("mtclient: read handshake frame: %w", err)
	}
	_, payload, err := mtproto.DecodePlain(frame)
	if err != nil {
		return err
	}
	got, err := mtproto.PeekConstructor(payload)
	if err != nil {
		return err
	}
	if got != want {
		if got == mtproto.CHandshakeError {
			var he mtproto.HandshakeError
			_ = mtproto.Decode(payload, &he)
			return fmt.Errorf("mtclient: server rejected the handshake: %s", he.Code)
		}
		return fmt.Errorf("mtclient: expected constructor %#x, got %#x", uint32(want), uint32(got))
	}
	return mtproto.Decode(payload, v)
}

// readLoop dispatches every inbound encrypted message.
func (c *Client) readLoop() {
	defer close(c.done)

	for {
		frame, err := c.fr.ReadFrame(c.br)
		if err != nil {
			if !c.closed.Load() {
				c.readErr.Store(&err)
				c.failPending(err)
			}
			return
		}

		msg, err := mtproto.Decrypt(c.authKey, frame, mtproto.ServerToClient)
		if err != nil {
			c.readErr.Store(&err)
			c.failPending(err)
			return
		}

		constructor, err := mtproto.PeekConstructor(msg.Body)
		if err != nil {
			continue
		}

		switch constructor {
		case mtproto.CRPCResult:
			var res mtproto.RPCResult
			if err := mtproto.Decode(msg.Body, &res); err != nil {
				continue
			}
			c.deliver(res.ReqMsgID, result{body: res.Result})

		case mtproto.CRPCError:
			var e mtproto.RPCError
			if err := mtproto.Decode(msg.Body, &e); err != nil {
				continue
			}
			c.deliver(e.ReqMsgID, result{err: &e})

		case mtproto.CBadServerSalt:
			// Adopt the corrected salt. This is why a salt rotation costs one
			// round trip rather than a reconnect.
			var bs mtproto.BadServerSalt
			if err := mtproto.Decode(msg.Body, &bs); err == nil && bs.NewSalt != 0 {
				c.salt.Store(bs.NewSalt)
			}

		case mtproto.CBadMsgNotify:
			var bm mtproto.BadMsgNotification
			if err := mtproto.Decode(msg.Body, &bm); err == nil {
				c.deliver(bm.BadMsgID, result{
					err: fmt.Errorf("mtclient: server rejected msg_id %d, code %d", bm.BadMsgID, bm.ErrorCode),
				})
			}

		case mtproto.CNewSessionReset:
			var ns mtproto.NewSessionCreated
			if err := mtproto.Decode(msg.Body, &ns); err == nil && ns.ServerSalt != 0 {
				c.salt.Store(ns.ServerSalt)
			}

		case mtproto.CPong:
			var p mtproto.Pong
			if err := mtproto.Decode(msg.Body, &p); err == nil {
				c.deliver(p.MsgID, result{body: json.RawMessage(`{"ok":true}`)})
			}

		case mtproto.CUpdate:
			if c.opts.OnUpdate != nil {
				var u mtproto.Update
				if err := mtproto.Decode(msg.Body, &u); err == nil {
					c.opts.OnUpdate(u)
				}
			}

		case mtproto.CMsgsAck:
			// Nothing to do: this client does not retransmit.
		}
	}
}

func (c *Client) deliver(reqMsgID int64, r result) {
	c.mu.Lock()
	ch, ok := c.pending[reqMsgID]
	if ok {
		delete(c.pending, reqMsgID)
	}
	c.mu.Unlock()

	if ok {
		ch <- r
		close(ch)
	}
}

func (c *Client) failPending(err error) {
	c.mu.Lock()
	pending := c.pending
	c.pending = make(map[int64]chan result)
	c.mu.Unlock()

	for _, ch := range pending {
		ch <- result{err: err}
		close(ch)
	}
}

// Invoke sends a method and waits for its answer.
func (c *Client) Invoke(ctx context.Context, id mtproto.ConstructorID, req any, resp any) error {
	if c.closed.Load() {
		return errors.New("mtclient: connection closed")
	}

	payload, err := mtproto.Encode(id, req)
	if err != nil {
		return err
	}

	msgID := c.msgIDs.Next(mtproto.KindFromClient)
	ch := make(chan result, 1)

	c.mu.Lock()
	c.pending[msgID] = ch
	c.mu.Unlock()

	msg := &mtproto.Message{
		Salt:      c.salt.Load(),
		SessionID: c.sessionID,
		MsgID:     msgID,
		SeqNo:     c.seqNo.Next(true),
		Body:      payload,
	}
	frame, err := mtproto.Encrypt(c.authKey, msg, mtproto.ClientToServer)
	if err != nil {
		c.cancelPending(msgID)
		return err
	}

	c.writeMu.Lock()
	_ = c.conn.SetWriteDeadline(time.Now().Add(c.opts.RequestTimeout))
	err = c.fr.WriteFrame(c.conn, frame)
	c.writeMu.Unlock()
	if err != nil {
		c.cancelPending(msgID)
		return fmt.Errorf("mtclient: write: %w", err)
	}

	timeout := time.NewTimer(c.opts.RequestTimeout)
	defer timeout.Stop()

	select {
	case <-ctx.Done():
		c.cancelPending(msgID)
		return ctx.Err()
	case <-timeout.C:
		c.cancelPending(msgID)
		return fmt.Errorf("mtclient: timed out after %s", c.opts.RequestTimeout)
	case <-c.done:
		if e := c.readErr.Load(); e != nil {
			return *e
		}
		return errors.New("mtclient: connection closed")
	case r := <-ch:
		if r.err != nil {
			return r.err
		}
		if resp == nil {
			return nil
		}
		return json.Unmarshal(r.body, resp)
	}
}

func (c *Client) cancelPending(msgID int64) {
	c.mu.Lock()
	delete(c.pending, msgID)
	c.mu.Unlock()
}

// AuthKeyID returns the negotiated key identifier.
func (c *Client) AuthKeyID() string { return c.authKey.IDHex() }

// UserID returns the bound account, or 0.
func (c *Client) UserID() int64 { return c.userID.Load() }

// Close tears the connection down.
func (c *Client) Close() error {
	if c.closed.Swap(true) {
		return nil
	}
	return c.conn.Close()
}

// ---------------------------------------------------------------------------
// Convenience wrappers
// ---------------------------------------------------------------------------

// Bind attaches an authenticated identity to the negotiated auth key.
func (c *Client) Bind(ctx context.Context, accessToken, platform, appVersion string) (mtproto.AuthBindResult, error) {
	var out mtproto.AuthBindResult
	err := c.Invoke(ctx, mtproto.CAuthBind, mtproto.AuthBind{
		AccessToken: accessToken, Platform: platform, AppVersion: appVersion,
	}, &out)
	if err != nil {
		return out, err
	}
	c.userID.Store(out.UserID)
	c.deviceID.Store(out.DeviceID)
	if out.ServerSalt != 0 {
		c.salt.Store(out.ServerSalt)
	}
	if out.SessionID != 0 {
		c.sessionID = out.SessionID
	}
	return out, nil
}

// Ping measures the round trip and keeps the connection warm.
func (c *Client) Ping(ctx context.Context) error {
	id, err := randomInt64()
	if err != nil {
		return err
	}
	return c.Invoke(ctx, mtproto.CPing, mtproto.Ping{PingID: id}, nil)
}

// SendMessage posts a message.
func (c *Client) SendMessage(ctx context.Context, req mtproto.SendMessage) (mtproto.SendMessageResult, error) {
	var out mtproto.SendMessageResult
	err := c.Invoke(ctx, mtproto.CSendMessage, req, &out)
	return out, err
}

// GetHistory pages backwards through a chat.
func (c *Client) GetHistory(ctx context.Context, req mtproto.GetHistory) (mtproto.GetHistoryResult, error) {
	var out mtproto.GetHistoryResult
	err := c.Invoke(ctx, mtproto.CGetHistory, req, &out)
	return out, err
}

// GetDifference is the reconnect catch-up.
func (c *Client) GetDifference(ctx context.Context, req mtproto.GetDifference) (mtproto.DifferenceResult, error) {
	var out mtproto.DifferenceResult
	err := c.Invoke(ctx, mtproto.CGetDifference, req, &out)
	return out, err
}

func randomInt64() (int64, error) {
	var b [8]byte
	if _, err := cryptoRead(b[:]); err != nil {
		return 0, err
	}
	v := int64(0)
	for _, x := range b {
		v = v<<8 | int64(x)
	}
	if v < 0 {
		v = -v
	}
	return v, nil
}
