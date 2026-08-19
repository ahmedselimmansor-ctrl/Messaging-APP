package mtclient_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pervagans/messaging-app/pkg/mtclient"
	"github.com/pervagans/messaging-app/pkg/mtproto"
	"github.com/pervagans/messaging-app/pkg/mtproto/transport"
)

// These tests drive the real client against a real server over a real TCP
// socket. Each layer has its own unit tests; this is the one that proves they
// compose — handshake, framing, obfuscation, envelope, dispatch — which is
// exactly where protocol bugs hide.

func TestEndToEndOverTCP(t *testing.T) {
	for _, tc := range []struct {
		name       string
		framing    string
		obfuscated bool
	}{
		{"abridged", "abridged", false},
		{"intermediate", "intermediate", false},
		{"padded", "padded", false},
		{"obfuscated-intermediate", "intermediate", true},
		{"obfuscated-abridged", "abridged", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newTestServer(t)
			defer srv.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			c, err := mtclient.Dial(ctx, mtclient.Options{
				Addr:               srv.Addr(),
				ServerPublicKeyPEM: srv.PublicKeyPEM,
				Framing:            tc.framing,
				Obfuscated:         tc.obfuscated,
				// Generous, because -race instruments every big.Int operation
				// in the Diffie-Hellman exchange and slows it by an order of
				// magnitude.
				DialTimeout:    30 * time.Second,
				RequestTimeout: 15 * time.Second,
			})
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer c.Close()

			if c.AuthKeyID() == "" {
				t.Fatal("handshake completed without an auth key id")
			}

			// A ping proves the encrypted channel works in both directions.
			if err := c.Ping(ctx); err != nil {
				t.Fatalf("ping: %v", err)
			}

			// And an RPC proves the dispatch layer above it does too.
			res, err := c.SendMessage(ctx, mtproto.SendMessage{
				ChatID: 42, Type: "text", Body: "hello over " + tc.name, RandomID: 12345,
			})
			if err != nil {
				t.Fatalf("send: %v", err)
			}
			if res.ChatID != 42 || res.Seq == 0 {
				t.Fatalf("unexpected send result: %+v", res)
			}
		})
	}
}

func TestEndToEndManyMessages(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	c, err := mtclient.Dial(ctx, mtclient.Options{
		Addr:               srv.Addr(),
		ServerPublicKeyPEM: srv.PublicKeyPEM,
		Framing:            "intermediate",
		RequestTimeout:     15 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	// Sequential sends over one connection. This exercises the msg_id
	// generator's monotonicity, the sequence counter's parity and the
	// server's replay window over a realistic number of messages.
	const n = 200
	seen := make(map[int64]bool, n)
	for i := 0; i < n; i++ {
		res, err := c.SendMessage(ctx, mtproto.SendMessage{
			ChatID: 7, Type: "text", Body: "message", RandomID: int64(i + 1),
		})
		if err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
		if seen[res.Seq] {
			t.Fatalf("sequence %d was assigned twice", res.Seq)
		}
		seen[res.Seq] = true
	}
	if len(seen) != n {
		t.Fatalf("got %d distinct sequences, want %d", len(seen), n)
	}
}

func TestEndToEndConcurrentRequests(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	c, err := mtclient.Dial(ctx, mtclient.Options{
		Addr:               srv.Addr(),
		ServerPublicKeyPEM: srv.PublicKeyPEM,
		Framing:            "intermediate",
		RequestTimeout:     20 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	// Concurrent in-flight requests on one connection. Responses arrive
	// out of order, so this is what proves the pending-request map correlates
	// answers to calls by msg_id rather than by arrival order.
	const workers = 20
	const each = 10

	var wg sync.WaitGroup
	errs := make(chan error, workers*each)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				res, err := c.SendMessage(ctx, mtproto.SendMessage{
					ChatID:   int64(worker + 1),
					Type:     "text",
					Body:     "concurrent",
					RandomID: int64(worker*1000 + i),
				})
				if err != nil {
					errs <- err
					return
				}
				// The echo server returns the chat id it was given; a
				// mismatch means a response was delivered to the wrong caller.
				if res.ChatID != int64(worker+1) {
					errs <- errors.New("response correlated to the wrong request")
					return
				}
			}
		}(w)
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent request: %v", err)
	}
}

func TestEndToEndRejectsWrongServerKey(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	// A different key entirely: this is the man-in-the-middle case, and the
	// client must refuse rather than complete a handshake with a stranger.
	_, otherPub := newRSAKey(t)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	_, err := mtclient.Dial(ctx, mtclient.Options{
		Addr:               srv.Addr(),
		ServerPublicKeyPEM: otherPub,
		Framing:            "intermediate",
	})
	if err == nil {
		t.Fatal("handshake succeeded against an unpinned server key")
	}
}

func TestEndToEndServerPushedUpdates(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()

	received := make(chan mtproto.Update, 4)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	c, err := mtclient.Dial(ctx, mtclient.Options{
		Addr:               srv.Addr(),
		ServerPublicKeyPEM: srv.PublicKeyPEM,
		Framing:            "intermediate",
		OnUpdate: func(u mtproto.Update) {
			select {
			case received <- u:
			default:
			}
		},
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	// The stub server pushes an update after every send, mirroring what the
	// real fanout does.
	if _, err := c.SendMessage(ctx, mtproto.SendMessage{
		ChatID: 99, Type: "text", Body: "trigger an update", RandomID: 1,
	}); err != nil {
		t.Fatalf("send: %v", err)
	}

	select {
	case u := <-received:
		if u.Kind != "new_message" || u.ChatID != 99 {
			t.Fatalf("unexpected update: %+v", u)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no update arrived")
	}
}

// ---------------------------------------------------------------------------
// A minimal MTProto server
// ---------------------------------------------------------------------------
//
// This is not the real gateway — it has no Redis, no Kafka and no upstream
// services — but it speaks the same protocol through the same packages, so a
// protocol regression fails here.

type testServer struct {
	ln           *transport.TCPListener
	PublicKeyPEM string
	cancel       context.CancelFunc
	seq          atomic.Int64
}

func newTestServer(t *testing.T) *testServer {
	t.Helper()

	privPEM, pubPEM := newRSAKey(t)
	serverKey, err := mtproto.LoadServerKey(privPEM)
	if err != nil {
		t.Fatalf("load server key: %v", err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	ln, err := transport.ListenTCP("127.0.0.1:0", log)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	s := &testServer{ln: ln, PublicKeyPEM: pubPEM, cancel: cancel}

	go func() {
		_ = ln.Serve(ctx, func(ctx context.Context, conn transport.Conn) {
			s.handle(ctx, conn, serverKey)
		})
	}()

	return s
}

func (s *testServer) Addr() string { return s.ln.Addr().String() }

func (s *testServer) Close() {
	s.cancel()
	_ = s.ln.Close()
}

func (s *testServer) handle(ctx context.Context, conn transport.Conn, serverKey *mtproto.ServerKey) {
	defer conn.Close()

	hs := mtproto.NewServerHandshake(serverKey, 30*time.Second)
	var authKey *mtproto.AuthKey
	var msgIDs mtproto.MsgIDGenerator
	var seqNo mtproto.SeqNoCounter
	validator := mtproto.NewMsgIDValidator()

	salt, err := mtproto.NewSalt()
	if err != nil {
		return
	}
	var sessionID int64
	var writeMu sync.Mutex

	sendPlain := func(id mtproto.ConstructorID, v any) error {
		payload, err := mtproto.Encode(id, v)
		if err != nil {
			return err
		}
		writeMu.Lock()
		defer writeMu.Unlock()
		return conn.WriteFrame(ctx, mtproto.EncodePlain(msgIDs.Next(mtproto.KindFromServerResponse), payload))
	}

	sendEncrypted := func(id mtproto.ConstructorID, v any) error {
		payload, err := mtproto.Encode(id, v)
		if err != nil {
			return err
		}
		msg := &mtproto.Message{
			Salt: salt, SessionID: sessionID,
			MsgID: msgIDs.Next(mtproto.KindFromServerResponse),
			SeqNo: seqNo.Next(true), Body: payload,
		}
		frame, err := mtproto.Encrypt(authKey, msg, mtproto.ServerToClient)
		if err != nil {
			return err
		}
		writeMu.Lock()
		defer writeMu.Unlock()
		return conn.WriteFrame(ctx, frame)
	}

	for {
		frame, err := conn.ReadFrame(ctx)
		if err != nil {
			return
		}

		keyID, err := mtproto.PeekAuthKeyID(frame)
		if err != nil {
			return
		}

		// --- handshake ---
		if keyID == 0 {
			if authKey != nil {
				return // plain messages are illegal once encrypted
			}
			_, payload, err := mtproto.DecodePlain(frame)
			if err != nil {
				return
			}
			constructor, err := mtproto.PeekConstructor(payload)
			if err != nil {
				return
			}

			switch constructor {
			case mtproto.CReqPQ:
				var req mtproto.ReqPQ
				if mtproto.Decode(payload, &req) != nil {
					return
				}
				res, err := hs.ReqPQ(req.Nonce)
				if err != nil || sendPlain(mtproto.CResPQ, res) != nil {
					return
				}

			case mtproto.CReqDHParams:
				var req mtproto.ReqDHParams
				if mtproto.Decode(payload, &req) != nil {
					return
				}
				res, err := hs.ReqDHParams(req)
				if err != nil {
					_ = sendPlain(mtproto.CHandshakeError, mtproto.HandshakeError{Code: "DH_PARAMS_INVALID"})
					return
				}
				if sendPlain(mtproto.CServerDHParams, res) != nil {
					return
				}

			case mtproto.CSetClientDHParams:
				var req mtproto.SetClientDHParams
				if mtproto.Decode(payload, &req) != nil {
					return
				}
				key, ok, err := hs.SetClientDHParams(req)
				if err != nil {
					_ = sendPlain(mtproto.CHandshakeError, mtproto.HandshakeError{Code: "DH_GEN_FAILED"})
					return
				}
				authKey = key
				if sendPlain(mtproto.CDHGenOK, ok) != nil {
					return
				}

			default:
				return
			}
			continue
		}

		// --- encrypted ---
		if authKey == nil {
			return
		}
		msg, err := mtproto.Decrypt(authKey, frame, mtproto.ClientToServer)
		if err != nil {
			return
		}
		if err := validator.Check(msg.MsgID); err != nil {
			_ = sendEncrypted(mtproto.CBadMsgNotify, mtproto.BadMsgNotification{
				BadMsgID: msg.MsgID, BadSeqNo: msg.SeqNo, ErrorCode: mtproto.BadMsgIDDuplicate,
			})
			continue
		}
		if sessionID == 0 {
			sessionID = msg.SessionID
		}

		constructor, err := mtproto.PeekConstructor(msg.Body)
		if err != nil {
			continue
		}

		switch constructor {
		case mtproto.CPing:
			var p mtproto.Ping
			_ = mtproto.Decode(msg.Body, &p)
			_ = sendEncrypted(mtproto.CPong, mtproto.Pong{
				MsgID: msg.MsgID, PingID: p.PingID, ServerTime: time.Now().Unix(),
			})

		case mtproto.CSendMessage:
			var req mtproto.SendMessage
			if mtproto.Decode(msg.Body, &req) != nil {
				continue
			}
			result := mtproto.SendMessageResult{
				MessageID: "test-message", ChatID: req.ChatID,
				Seq: s.seq.Add(1), Date: time.Now().Unix(),
			}
			body, _ := json.Marshal(result)
			_ = sendEncrypted(mtproto.CRPCResult, mtproto.RPCResult{
				ReqMsgID: msg.MsgID, Result: body,
			})

			// Mirror the real fanout: a send produces an update.
			_ = sendEncrypted(mtproto.CUpdate, mtproto.Update{
				Kind: "new_message", ChatID: req.ChatID,
				Seq: result.Seq, Date: time.Now().UnixMilli(),
			})

		default:
			_ = sendEncrypted(mtproto.CRPCError, mtproto.RPCError{
				ReqMsgID: msg.MsgID, Code: 400, Message: "METHOD_NOT_FOUND",
			})
		}
	}
}

func newRSAKey(t *testing.T) (privPEM, pubPEM string) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	privPEM = string(pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv),
	}))

	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	pubPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	return privPEM, pubPEM
}
