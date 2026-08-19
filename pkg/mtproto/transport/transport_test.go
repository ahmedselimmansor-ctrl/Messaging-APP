package transport

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pervagans/messaging-app/pkg/mtproto/codec"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// echoHandler reads frames and writes them straight back, which is enough to
// prove the transport preserves message boundaries and content.
func echoHandler(t *testing.T) (Handler, *sync.WaitGroup) {
	t.Helper()
	var wg sync.WaitGroup
	return func(ctx context.Context, c Conn) {
		wg.Add(1)
		defer wg.Done()
		defer c.Close()
		for {
			frame, err := c.ReadFrame(ctx)
			if err != nil {
				return
			}
			if err := c.WriteFrame(ctx, frame); err != nil {
				return
			}
		}
	}, &wg
}

func TestTCPTransportPlainFraming(t *testing.T) {
	ln, err := ListenTCP("127.0.0.1:0", testLogger())
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h, _ := echoHandler(t)
	go func() { _ = ln.Serve(ctx, h) }()

	for _, framingName := range []string{"abridged", "intermediate", "padded"} {
		t.Run(framingName, func(t *testing.T) {
			conn, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer conn.Close()

			framing, _ := codec.ByName(framingName)
			if err := codec.WriteMagic(conn, framing); err != nil {
				t.Fatalf("write magic: %v", err)
			}

			payload := bytes.Repeat([]byte{0x37}, 128)
			if err := framing.WriteFrame(conn, payload); err != nil {
				t.Fatalf("write: %v", err)
			}

			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			got, err := framing.ReadFrame(bufio.NewReader(conn))
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("echo mismatch: %d bytes back, %d sent", len(got), len(payload))
			}
		})
	}
}

func TestTCPTransportObfuscated(t *testing.T) {
	ln, err := ListenTCP("127.0.0.1:0", testLogger())
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h, _ := echoHandler(t)
	go func() { _ = ln.Serve(ctx, h) }()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close()

	framing, _ := codec.ByName("intermediate")
	oc, err := codec.DialObfuscated(raw, framing, 1)
	if err != nil {
		t.Fatalf("obfuscated dial: %v", err)
	}

	payload := bytes.Repeat([]byte{0x5C}, 256)
	if err := oc.Codec.WriteFrame(oc, payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	_ = raw.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := oc.Codec.ReadFrame(bufio.NewReader(oc))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("obfuscated echo mismatch")
	}
}

func TestUDPTransportFragmentation(t *testing.T) {
	ln, err := ListenUDP("127.0.0.1:0", testLogger())
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h, _ := echoHandler(t)
	go func() { _ = ln.Serve(ctx, h) }()

	client, err := DialUDP(ctx, ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	// A payload well past one datagram forces fragmentation and reassembly in
	// both directions.
	for _, size := range []int{64, udpMaxPayload - 1, udpMaxPayload, udpMaxPayload*3 + 7, 64 << 10} {
		payload := bytes.Repeat([]byte{byte(size % 251)}, size)
		if err := client.WriteFrame(ctx, payload); err != nil {
			t.Fatalf("write %d bytes: %v", size, err)
		}

		readCtx, readCancel := context.WithTimeout(ctx, 5*time.Second)
		got, err := client.ReadFrame(readCtx)
		readCancel()
		if err != nil {
			t.Fatalf("read %d bytes: %v", size, err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("size %d: echoed %d bytes, content mismatch", size, len(got))
		}
	}
}

func TestUDPRejectsUnknownConnection(t *testing.T) {
	ln, err := ListenUDP("127.0.0.1:0", testLogger())
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var handled int
	var mu sync.Mutex
	go func() {
		_ = ln.Serve(ctx, func(_ context.Context, c Conn) {
			mu.Lock()
			handled++
			mu.Unlock()
			_ = c.Close()
		})
	}()

	pc, err := net.Dial("udp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer pc.Close()

	// A data datagram for a connection the server has never seen, without the
	// hello flag, must not create state.
	hdr := udpHeader{flags: udpFlagData, connID: 0xDEADBEEF, fragCount: 1}
	if _, err := pc.Write(hdr.marshal([]byte("ignored"))); err != nil {
		t.Fatalf("write: %v", err)
	}
	time.Sleep(150 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if handled != 0 {
		t.Fatalf("server created a connection for an unsolicited datagram (handled=%d)", handled)
	}
	if ln.Active() != 0 {
		t.Fatalf("server tracks %d connections, want 0", ln.Active())
	}
}

func TestUDPDropsGarbage(t *testing.T) {
	ln, err := ListenUDP("127.0.0.1:0", testLogger())
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = ln.Serve(ctx, func(context.Context, Conn) {}) }()

	pc, err := net.Dial("udp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer pc.Close()

	// Random bytes, a truncated header, and a header claiming an impossible
	// fragment count must all be discarded without panicking the demux loop.
	garbage := [][]byte{
		[]byte("hello there"),
		make([]byte, 3),
		func() []byte {
			h := udpHeader{flags: udpFlagHello, connID: 1, fragCount: 0}
			return h.marshal(nil)
		}(),
	}
	for _, g := range garbage {
		if _, err := pc.Write(g); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	time.Sleep(100 * time.Millisecond)

	if ln.Active() != 0 {
		t.Fatalf("garbage created %d connections", ln.Active())
	}
}

func TestWebSocketTransport(t *testing.T) {
	ln, err := ListenWS(WSOptions{Addr: "127.0.0.1:0", Path: "/mtproto"}, testLogger())
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h, _ := echoHandler(t)
	go func() { _ = ln.Serve(ctx, h) }()

	url := "ws://" + ln.Addr().String() + "/mtproto"
	ws, resp, err := websocket.DefaultDialer.Dial(url, http.Header{})
	if err != nil {
		t.Fatalf("ws dial %s: %v", url, err)
	}
	if resp != nil {
		_ = resp.Body.Close()
	}
	defer ws.Close()

	payload := bytes.Repeat([]byte{0x91}, 1024)
	if err := ws.WriteMessage(websocket.BinaryMessage, payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	_ = ws.SetReadDeadline(time.Now().Add(5 * time.Second))
	msgType, got, err := ws.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if msgType != websocket.BinaryMessage {
		t.Fatalf("message type = %d, want binary", msgType)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("websocket echo mismatch")
	}
}

func TestWebSocketRejectsForeignOrigin(t *testing.T) {
	ln, err := ListenWS(WSOptions{
		Addr:           "127.0.0.1:0",
		Path:           "/mtproto",
		AllowedOrigins: []string{"https://app.example.com"},
	}, testLogger())
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = ln.Serve(ctx, func(context.Context, Conn) {}) }()

	url := "ws://" + ln.Addr().String() + "/mtproto"
	_, resp, err := websocket.DefaultDialer.Dial(url, http.Header{
		"Origin": []string{"https://evil.example"},
	})
	if err == nil {
		t.Fatal("connection from a disallowed origin was accepted")
	}
	if resp != nil {
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", resp.StatusCode)
		}
	}
}

func TestWSClientIPFromForwardedFor(t *testing.T) {
	l := &WSListener{TrustedProxyCount: 1}
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:5555"

	// One trusted proxy: the real client is the last-but-one entry, so a
	// client that forges an extra hop cannot make itself look like 1.2.3.4.
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 203.0.113.9, 35.191.0.1")
	if got := l.clientIP(r).String(); !strings.Contains(got, "203.0.113.9") {
		t.Fatalf("client ip = %s, want 203.0.113.9", got)
	}

	r.Header.Del("X-Forwarded-For")
	if got := l.clientIP(r).String(); !strings.Contains(got, "10.0.0.1") {
		t.Fatalf("fallback client ip = %s, want 10.0.0.1", got)
	}
}

func TestTCPConnectionLimit(t *testing.T) {
	ln, err := ListenTCP("127.0.0.1:0", testLogger())
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ln.MaxConnections = 1

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hold := make(chan struct{})
	go func() {
		_ = ln.Serve(ctx, func(_ context.Context, c Conn) {
			<-hold
			_ = c.Close()
		})
	}()

	framing, _ := codec.ByName("intermediate")

	first, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial 1: %v", err)
	}
	defer first.Close()
	_ = codec.WriteMagic(first, framing)
	_ = framing.WriteFrame(first, bytes.Repeat([]byte{1}, 16))
	time.Sleep(100 * time.Millisecond)

	second, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial 2: %v", err)
	}
	defer second.Close()

	// The second connection is over the cap and must be closed immediately.
	_ = second.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if _, err := second.Read(buf); err == nil {
		t.Fatal("connection over the cap was not closed")
	}

	close(hold)
}
