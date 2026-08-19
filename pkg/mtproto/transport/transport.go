// Package transport carries MTProto frames over TCP, UDP or WebSocket.
//
// The three exist because networks differ, not because we like variety:
//
//	TCP        the default. Ordered, reliable, works everywhere a socket works.
//	UDP        for lossy or high-latency links, where TCP's head-of-line
//	           blocking means one dropped packet stalls every message behind
//	           it. Ordering and retransmission move into the application, so a
//	           lost typing indicator never delays a text message.
//	WebSocket  the fallback for restrictive networks — corporate proxies,
//	           captive portals, hotel wifi — that only pass HTTP(S). Also what
//	           the browser client uses, since browsers cannot open raw sockets.
//
// All three present the same Conn interface, so the session layer above is
// written once and does not know which one it is talking over.
package transport

import (
	"context"
	"errors"
	"net"
	"time"
)

// Kind identifies a transport.
type Kind string

const (
	KindTCP Kind = "tcp"
	KindUDP Kind = "udp"
	KindWS  Kind = "ws"
)

// Errors.
var (
	// ErrClosed is returned by a Conn after Close.
	ErrClosed = errors.New("transport: connection closed")
	// ErrTimeout is returned when a read or write exceeds its deadline.
	ErrTimeout = errors.New("transport: deadline exceeded")
)

// Conn is one client connection carrying MTProto frames.
//
// Implementations must be safe for one reader goroutine and one writer
// goroutine running concurrently. They are *not* safe for two concurrent
// writers; the session layer funnels all writes through a single goroutine.
type Conn interface {
	// ReadFrame returns the next complete MTProto frame.
	ReadFrame(ctx context.Context) ([]byte, error)
	// WriteFrame writes one complete MTProto frame.
	WriteFrame(ctx context.Context, frame []byte) error
	// Close releases the connection. It is safe to call more than once.
	Close() error
	// RemoteAddr identifies the peer, for rate limiting and audit logs.
	RemoteAddr() net.Addr
	// Kind reports the transport.
	Kind() Kind
	// Framing reports the codec in use, for metrics.
	Framing() string
	// SetIdleTimeout bounds how long the connection may sit silent.
	SetIdleTimeout(d time.Duration)
}

// Handler is invoked once per accepted connection. It owns the connection and
// must close it when done.
type Handler func(ctx context.Context, c Conn)

// Listener accepts connections of one kind.
type Listener interface {
	// Serve blocks, dispatching accepted connections to h, until ctx is
	// cancelled or a fatal error occurs.
	Serve(ctx context.Context, h Handler) error
	// Addr is the bound address.
	Addr() net.Addr
	// Close stops accepting.
	Close() error
}

// defaultIdleTimeout is how long a connection may be silent before we reclaim
// it. Mobile clients ping every 60s, so 150s tolerates two missed pings — long
// enough to survive a subway tunnel, short enough that a pod's connection
// table does not fill with dead sockets.
const defaultIdleTimeout = 150 * time.Second

// maxFrameSize mirrors the codec limit so every transport refuses oversized
// input before allocating.
const maxFrameSize = 16 << 20
