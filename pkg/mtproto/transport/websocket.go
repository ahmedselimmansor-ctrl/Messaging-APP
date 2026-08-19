package transport

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

// WebSocket transport.
//
// This is the fallback path and the browser path. Two consequences shape it:
//
//   - It terminates behind the Global External HTTPS Load Balancer, not the
//     TCP one, so the client's real address arrives in X-Forwarded-For and
//     must be taken from there. Trusting RemoteAddr here would rate-limit the
//     load balancer instead of the user.
//   - WebSocket already frames messages, so no MTProto transport codec is
//     needed: one binary WebSocket message carries exactly one MTProto frame.
//     Layering the abridged codec on top would add bytes for nothing.
type WSListener struct {
	srv  *http.Server
	mux  *http.ServeMux
	ln   net.Listener
	log  *slog.Logger
	up   websocket.Upgrader
	path string

	// TrustedProxyCount is how many hops of X-Forwarded-For to skip from the
	// right. With one Google load balancer in front, the client address is
	// the last-but-one entry; taking the leftmost value would let a client
	// spoof its own address by sending the header itself.
	TrustedProxyCount int

	MaxConnections int64
	active         atomic.Int64

	wg sync.WaitGroup
}

// WSOptions configures the listener.
type WSOptions struct {
	Addr string
	// Path is the endpoint clients connect to, e.g. /mtproto.
	Path string
	// AllowedOrigins restricts browser connections. An empty list means
	// same-origin only; "*" disables the check, which is only acceptable for
	// non-browser clients that do not send an Origin header at all.
	AllowedOrigins []string
	// ReadBufferSize and WriteBufferSize tune per-connection memory. With
	// tens of thousands of connections per pod this is the dominant term in
	// the gateway's memory footprint: 4KB each means ~320MB at 40k
	// connections, so they are kept deliberately small.
	ReadBufferSize  int
	WriteBufferSize int
}

// ListenWS builds the WebSocket listener.
func ListenWS(o WSOptions, log *slog.Logger) (*WSListener, error) {
	if o.Path == "" {
		o.Path = "/mtproto"
	}
	if o.ReadBufferSize == 0 {
		o.ReadBufferSize = 4096
	}
	if o.WriteBufferSize == 0 {
		o.WriteBufferSize = 4096
	}

	allowed := make(map[string]bool, len(o.AllowedOrigins))
	wildcard := false
	for _, origin := range o.AllowedOrigins {
		if origin == "*" {
			wildcard = true
			continue
		}
		allowed[strings.ToLower(strings.TrimSpace(origin))] = true
	}

	l := &WSListener{
		log:               log.With("transport", "ws", "addr", o.Addr, "path", o.Path),
		path:              o.Path,
		TrustedProxyCount: 1,
		MaxConnections:    50_000,
		up: websocket.Upgrader{
			ReadBufferSize:  o.ReadBufferSize,
			WriteBufferSize: o.WriteBufferSize,
			// Compression is deliberately off. The payload is already
			// encrypted, so it does not compress, and enabling permessage
			// -deflate would spend CPU and a 32KB window per connection to
			// achieve nothing.
			EnableCompression: false,
			HandshakeTimeout:  10 * time.Second,
			CheckOrigin: func(r *http.Request) bool {
				origin := r.Header.Get("Origin")
				if origin == "" {
					return true // native clients send no Origin
				}
				if wildcard {
					return true
				}
				return allowed[strings.ToLower(origin)]
			},
			Subprotocols: []string{"mtproto"},
		},
	}

	mux := http.NewServeMux()
	l.srv = &http.Server{
		Addr:              o.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	l.mux = mux

	// Bind here rather than in Serve so Addr() is valid — and race-free — the
	// moment the constructor returns. It also means a port conflict is
	// reported at startup instead of from a goroutine nobody is watching.
	ln, err := net.Listen("tcp", o.Addr)
	if err != nil {
		return nil, fmt.Errorf("transport: listen ws %s: %w", o.Addr, err)
	}
	l.ln = ln
	l.log = l.log.With("addr", ln.Addr().String())

	return l, nil
}

// Addr returns the bound address.
func (l *WSListener) Addr() net.Addr { return l.ln.Addr() }

// Serve starts the HTTP server and upgrades connections.
func (l *WSListener) Serve(ctx context.Context, h Handler) error {
	l.mux.HandleFunc(l.path, func(w http.ResponseWriter, r *http.Request) {
		if n := l.active.Add(1); l.MaxConnections > 0 && n > l.MaxConnections {
			l.active.Add(-1)
			http.Error(w, "gateway at capacity", http.StatusServiceUnavailable)
			return
		}

		ws, err := l.up.Upgrade(w, r, nil)
		if err != nil {
			// Upgrade already wrote a response.
			l.active.Add(-1)
			l.log.Debug("websocket upgrade failed", "error", err)
			return
		}

		c := newWSConn(ws, l.clientIP(r))
		l.wg.Add(1)
		go func() {
			defer l.wg.Done()
			defer l.active.Add(-1)
			h(ctx, c)
		}()
	})

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_ = l.srv.Shutdown(shutdownCtx)
	}()

	if err := l.srv.Serve(l.ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("transport: websocket serve: %w", err)
	}
	l.wg.Wait()
	return nil
}

// clientIP extracts the real client address from behind the load balancer.
func (l *WSListener) clientIP(r *http.Request) net.Addr {
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		parts := strings.Split(xff, ",")
		// Count from the right: each proxy appends, so the entry
		// TrustedProxyCount positions from the end is the address our
		// outermost trusted proxy observed.
		idx := len(parts) - 1 - l.TrustedProxyCount
		if idx < 0 {
			idx = 0
		}
		if ip := strings.TrimSpace(parts[idx]); ip != "" {
			if host, _, err := net.SplitHostPort(ip); err == nil {
				ip = host
			}
			if parsed := net.ParseIP(ip); parsed != nil {
				return &net.TCPAddr{IP: parsed}
			}
		}
	}
	if host, portStr, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		if parsed := net.ParseIP(host); parsed != nil {
			port := 0
			_, _ = fmt.Sscanf(portStr, "%d", &port)
			return &net.TCPAddr{IP: parsed, Port: port}
		}
	}
	return dummyAddr(r.RemoteAddr)
}

// Close stops the listener.
func (l *WSListener) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := l.srv.Shutdown(ctx)
	l.wg.Wait()
	return err
}

// Active reports the current connection count.
func (l *WSListener) Active() int64 { return l.active.Load() }

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------

type wsConn struct {
	ws     *websocket.Conn
	remote net.Addr

	idle atomic.Int64

	writeMu sync.Mutex
	closed  atomic.Bool
}

func newWSConn(ws *websocket.Conn, remote net.Addr) *wsConn {
	c := &wsConn{ws: ws, remote: remote}
	c.idle.Store(int64(defaultIdleTimeout))

	ws.SetReadLimit(maxFrameSize)
	// A pong resets the read deadline, which is how a healthy but quiet
	// connection stays alive without any application traffic.
	ws.SetPongHandler(func(string) error {
		return ws.SetReadDeadline(time.Now().Add(time.Duration(c.idle.Load())))
	})
	return c
}

func (c *wsConn) ReadFrame(ctx context.Context) ([]byte, error) {
	if c.closed.Load() {
		return nil, ErrClosed
	}

	deadline := time.Now().Add(time.Duration(c.idle.Load()))
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := c.ws.SetReadDeadline(deadline); err != nil {
		return nil, err
	}

	for {
		msgType, data, err := c.ws.ReadMessage()
		if err != nil {
			if c.closed.Load() {
				return nil, ErrClosed
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return nil, ErrTimeout
			}
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				return nil, ErrClosed
			}
			return nil, err
		}
		if msgType != websocket.BinaryMessage {
			// MTProto frames are binary. A text message is either a confused
			// client or a probe; ignore it rather than tear the connection
			// down, since browsers occasionally send keepalive text.
			continue
		}
		return data, nil
	}
}

func (c *wsConn) WriteFrame(ctx context.Context, frame []byte) error {
	if c.closed.Load() {
		return ErrClosed
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	deadline := time.Now().Add(30 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := c.ws.SetWriteDeadline(deadline); err != nil {
		return err
	}
	return c.ws.WriteMessage(websocket.BinaryMessage, frame)
}

// Ping sends a WebSocket ping, used by the gateway's keepalive loop.
func (c *wsConn) Ping(ctx context.Context) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	deadline := time.Now().Add(10 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	return c.ws.WriteControl(websocket.PingMessage, nil, deadline)
}

func (c *wsConn) Close() error {
	if c.closed.Swap(true) {
		return nil
	}
	// A clean close frame lets the browser distinguish "server went away
	// deliberately" from "network died", which changes its reconnect backoff.
	c.writeMu.Lock()
	_ = c.ws.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
		time.Now().Add(time.Second))
	c.writeMu.Unlock()
	return c.ws.Close()
}

func (c *wsConn) RemoteAddr() net.Addr { return c.remote }
func (c *wsConn) Kind() Kind           { return KindWS }
func (c *wsConn) Framing() string      { return "websocket" }

func (c *wsConn) SetIdleTimeout(d time.Duration) {
	if d > 0 {
		c.idle.Store(int64(d))
	}
}

// dummyAddr renders a string as a net.Addr for logging.
type dummyAddr string

func (d dummyAddr) Network() string { return "tcp" }
func (d dummyAddr) String() string  { return string(d) }
