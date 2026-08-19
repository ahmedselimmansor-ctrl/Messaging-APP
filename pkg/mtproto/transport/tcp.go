package transport

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pervagans/messaging-app/pkg/mtproto/codec"
)

// TCPListener accepts raw MTProto connections.
//
// It sits behind the Network Load Balancer in TCP passthrough mode, so the
// client's source address arrives intact — no PROXY protocol header to parse
// and no X-Forwarded-For to trust. That is why the rate limiter can key on
// RemoteAddr directly.
type TCPListener struct {
	ln  net.Listener
	log *slog.Logger

	// AllowObfuscated enables the obfuscation2 wrapper. On by default; the
	// only reason to turn it off is a test that wants readable packet dumps.
	AllowObfuscated bool
	// HandshakeTimeout bounds how long a connection may take to declare its
	// framing. A socket that connects and says nothing is the cheapest
	// possible attack, so it must not hold a slot for long.
	HandshakeTimeout time.Duration
	// MaxConnections caps concurrent connections per pod. Beyond this we
	// close immediately rather than degrade everyone.
	MaxConnections int64

	active atomic.Int64
	wg     sync.WaitGroup
}

// ListenTCP binds a TCP listener.
func ListenTCP(addr string, log *slog.Logger) (*TCPListener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("transport: listen tcp %s: %w", addr, err)
	}
	return &TCPListener{
		ln:               ln,
		log:              log.With("transport", "tcp", "addr", ln.Addr().String()),
		AllowObfuscated:  true,
		HandshakeTimeout: 10 * time.Second,
		MaxConnections:   50_000,
	}, nil
}

// Addr returns the bound address.
func (l *TCPListener) Addr() net.Addr { return l.ln.Addr() }

// Serve accepts connections until ctx is cancelled.
func (l *TCPListener) Serve(ctx context.Context, h Handler) error {
	// Unblock Accept on shutdown.
	go func() {
		<-ctx.Done()
		_ = l.ln.Close()
	}()

	for {
		conn, err := l.ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				l.wg.Wait()
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			// A transient accept error (fd exhaustion) must not kill the
			// listener; back off and keep going.
			l.log.Error("accept failed", "error", err)
			select {
			case <-ctx.Done():
				l.wg.Wait()
				return nil
			case <-time.After(50 * time.Millisecond):
			}
			continue
		}

		if n := l.active.Add(1); l.MaxConnections > 0 && n > l.MaxConnections {
			l.active.Add(-1)
			l.log.Warn("connection refused: pod at capacity",
				"remote", conn.RemoteAddr().String(), "active", n-1)
			_ = conn.Close()
			continue
		}

		l.wg.Add(1)
		go func() {
			defer l.wg.Done()
			defer l.active.Add(-1)
			l.handle(ctx, conn, h)
		}()
	}
}

func (l *TCPListener) handle(ctx context.Context, raw net.Conn, h Handler) {
	if tc, ok := raw.(*net.TCPConn); ok {
		// Nagle batches small writes, which is exactly wrong for a chat
		// protocol: a 60-byte message would sit in the kernel waiting for
		// company and add up to 40ms of latency.
		_ = tc.SetNoDelay(true)
		// Keepalive detects a peer that vanished without a FIN — the usual
		// outcome when a phone loses signal.
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}

	c, err := l.upgrade(raw)
	if err != nil {
		l.log.Debug("connection setup failed",
			"remote", raw.RemoteAddr().String(), "error", err)
		_ = raw.Close()
		return
	}

	h(ctx, c)
}

// upgrade performs framing detection and, when present, the obfuscation
// handshake.
func (l *TCPListener) upgrade(raw net.Conn) (Conn, error) {
	_ = raw.SetReadDeadline(time.Now().Add(l.HandshakeTimeout))

	br := bufio.NewReaderSize(raw, 16<<10)

	// A recognised magic prefix means a plain connection.
	if first, err := br.Peek(1); err == nil && first[0] == 0xef {
		framing, err := codec.Detect(br)
		if err != nil {
			return nil, err
		}
		_ = raw.SetReadDeadline(time.Time{})
		return newTCPConn(raw, br, framing), nil
	}
	head, err := br.Peek(4)
	if err != nil {
		return nil, fmt.Errorf("transport: read framing prefix: %w", err)
	}
	switch uint32(head[0]) | uint32(head[1])<<8 | uint32(head[2])<<16 | uint32(head[3])<<24 {
	case 0xeeeeeeee, 0xdddddddd:
		framing, err := codec.Detect(br)
		if err != nil {
			return nil, err
		}
		_ = raw.SetReadDeadline(time.Time{})
		return newTCPConn(raw, br, framing), nil
	}

	if !l.AllowObfuscated {
		return nil, codec.ErrUnknownMagic
	}

	// Everything else is treated as an obfuscated connection: 64 bytes of
	// key material whose decryption reveals the framing.
	oc, err := codec.AcceptObfuscated(raw, br)
	if err != nil {
		return nil, err
	}
	_ = raw.SetReadDeadline(time.Time{})

	// Reads must now flow through the obfuscation wrapper. The bufio.Reader
	// used for detection is spent — everything it buffered has been consumed
	// by AcceptObfuscated — so a fresh one is layered on the wrapper.
	return newTCPConn(oc, bufio.NewReaderSize(oc, 16<<10), oc.Codec), nil
}

// Close stops the listener and waits for in-flight connections.
func (l *TCPListener) Close() error {
	err := l.ln.Close()
	l.wg.Wait()
	return err
}

// Active reports the current connection count, exported for metrics.
func (l *TCPListener) Active() int64 { return l.active.Load() }

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------

type tcpConn struct {
	c       net.Conn
	br      *bufio.Reader
	bw      *bufio.Writer
	framing codec.Codec

	idle atomic.Int64 // idle timeout in nanoseconds

	writeMu sync.Mutex
	closed  atomic.Bool
}

func newTCPConn(c net.Conn, br *bufio.Reader, framing codec.Codec) *tcpConn {
	tc := &tcpConn{
		c:       c,
		br:      br,
		bw:      bufio.NewWriterSize(c, 16<<10),
		framing: framing,
	}
	tc.idle.Store(int64(defaultIdleTimeout))
	return tc
}

func (t *tcpConn) ReadFrame(ctx context.Context) ([]byte, error) {
	if t.closed.Load() {
		return nil, ErrClosed
	}

	deadline := time.Now().Add(time.Duration(t.idle.Load()))
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := t.c.SetReadDeadline(deadline); err != nil {
		return nil, err
	}

	frame, err := t.framing.ReadFrame(t.br)
	if err != nil {
		if t.closed.Load() {
			return nil, ErrClosed
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return nil, ErrTimeout
		}
		if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
			return nil, ErrClosed
		}
		return nil, err
	}
	if len(frame) > maxFrameSize {
		return nil, codec.ErrFrameTooLarge
	}
	return frame, nil
}

func (t *tcpConn) WriteFrame(ctx context.Context, frame []byte) error {
	if t.closed.Load() {
		return ErrClosed
	}

	t.writeMu.Lock()
	defer t.writeMu.Unlock()

	deadline := time.Now().Add(30 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := t.c.SetWriteDeadline(deadline); err != nil {
		return err
	}

	if err := t.framing.WriteFrame(t.bw, frame); err != nil {
		return err
	}
	// Flush every frame: a buffered chat message is an undelivered one, and
	// the buffer exists to coalesce the framing header with the body, not to
	// delay delivery.
	return t.bw.Flush()
}

func (t *tcpConn) Close() error {
	if t.closed.Swap(true) {
		return nil
	}
	return t.c.Close()
}

func (t *tcpConn) RemoteAddr() net.Addr { return t.c.RemoteAddr() }
func (t *tcpConn) Kind() Kind           { return KindTCP }
func (t *tcpConn) Framing() string      { return t.framing.Name() }

func (t *tcpConn) SetIdleTimeout(d time.Duration) {
	if d > 0 {
		t.idle.Store(int64(d))
	}
}
