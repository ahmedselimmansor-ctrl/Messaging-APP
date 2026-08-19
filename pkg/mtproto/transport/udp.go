package transport

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// UDP transport.
//
// UDP gives us none of what TCP gives us — no connection, no ordering, no
// retransmission, no path validation — so all four are rebuilt here, with the
// specific trade-offs a chat protocol wants:
//
//   - Connections are identified by a client-chosen 64-bit connection id
//     rather than by the 4-tuple, so a phone switching from wifi to cellular
//     keeps its session instead of reconnecting.
//   - Messages larger than one datagram are fragmented and reassembled with a
//     bounded, time-limited buffer. An incomplete message is dropped, never
//     retried at this layer: the MTProto layer above already retransmits
//     unacknowledged messages, and duplicating that here would fight it.
//   - A datagram arriving from a *new* address for a known connection does not
//     immediately move the connection. The server first challenges the new
//     path with a random token and only migrates once the client echoes it
//     back. Without that check, anyone who guesses a connection id could
//     redirect a victim's server-to-client traffic to themselves.
//
// The datagram header is 24 bytes:
//
//	magic(2) ‖ version(1) ‖ flags(1) ‖ conn_id(8) ‖ msg_seq(4) ‖
//	frag_index(2) ‖ frag_count(2) ‖ payload_len(2) ‖ reserved(2)

const (
	udpMagic   uint16 = 0x4D51 // "MQ"
	udpVersion byte   = 1

	udpHeaderSize = 24

	// udpMaxPayload keeps a datagram inside a conservative 1280-byte MTU,
	// the IPv6 minimum, so we never rely on fragmentation at the IP layer —
	// IP-fragmented UDP is dropped by a depressing number of middleboxes.
	udpMaxPayload = 1280 - udpHeaderSize - 48 // leave room for IP/UDP headers

	// udpMaxFragments bounds a single logical message.
	udpMaxFragments = 512

	// udpReassemblyTTL is how long partial messages wait for their missing
	// fragments before being discarded.
	udpReassemblyTTL = 3 * time.Second
)

// Datagram flags.
const (
	udpFlagData          byte = 1 << 0
	udpFlagPathChallenge byte = 1 << 1
	udpFlagPathResponse  byte = 1 << 2
	udpFlagClose         byte = 1 << 3
	udpFlagHello         byte = 1 << 4
)

var errBadDatagram = errors.New("transport: malformed datagram")

type udpHeader struct {
	flags      byte
	connID     uint64
	msgSeq     uint32
	fragIndex  uint16
	fragCount  uint16
	payloadLen uint16
}

func (h udpHeader) marshal(payload []byte) []byte {
	out := make([]byte, udpHeaderSize+len(payload))
	binary.BigEndian.PutUint16(out[0:2], udpMagic)
	out[2] = udpVersion
	out[3] = h.flags
	binary.BigEndian.PutUint64(out[4:12], h.connID)
	binary.BigEndian.PutUint32(out[12:16], h.msgSeq)
	binary.BigEndian.PutUint16(out[16:18], h.fragIndex)
	binary.BigEndian.PutUint16(out[18:20], h.fragCount)
	binary.BigEndian.PutUint16(out[20:22], uint16(len(payload)))
	copy(out[udpHeaderSize:], payload)
	return out
}

func parseUDP(b []byte) (udpHeader, []byte, error) {
	if len(b) < udpHeaderSize {
		return udpHeader{}, nil, errBadDatagram
	}
	if binary.BigEndian.Uint16(b[0:2]) != udpMagic || b[2] != udpVersion {
		return udpHeader{}, nil, errBadDatagram
	}
	h := udpHeader{
		flags:      b[3],
		connID:     binary.BigEndian.Uint64(b[4:12]),
		msgSeq:     binary.BigEndian.Uint32(b[12:16]),
		fragIndex:  binary.BigEndian.Uint16(b[16:18]),
		fragCount:  binary.BigEndian.Uint16(b[18:20]),
		payloadLen: binary.BigEndian.Uint16(b[20:22]),
	}
	if int(h.payloadLen) != len(b)-udpHeaderSize {
		return udpHeader{}, nil, errBadDatagram
	}
	if h.fragCount == 0 || h.fragCount > udpMaxFragments || h.fragIndex >= h.fragCount {
		return udpHeader{}, nil, errBadDatagram
	}
	return h, b[udpHeaderSize:], nil
}

// UDPListener demultiplexes datagrams into per-connection channels.
type UDPListener struct {
	pc  *net.UDPConn
	log *slog.Logger

	// MaxConnections caps how many logical connections one pod tracks.
	MaxConnections int

	mu    sync.RWMutex
	conns map[uint64]*udpConn

	wg     sync.WaitGroup
	closed atomic.Bool
}

// ListenUDP binds a UDP socket.
func ListenUDP(addr string, log *slog.Logger) (*UDPListener, error) {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("transport: resolve udp %s: %w", addr, err)
	}
	pc, err := net.ListenUDP("udp", ua)
	if err != nil {
		return nil, fmt.Errorf("transport: listen udp %s: %w", addr, err)
	}
	// A large receive buffer absorbs a burst without the kernel dropping
	// datagrams while our demux loop is scheduled out.
	_ = pc.SetReadBuffer(4 << 20)
	_ = pc.SetWriteBuffer(4 << 20)

	return &UDPListener{
		pc:             pc,
		log:            log.With("transport", "udp", "addr", pc.LocalAddr().String()),
		MaxConnections: 50_000,
		conns:          make(map[uint64]*udpConn),
	}, nil
}

// Addr returns the bound address.
func (l *UDPListener) Addr() net.Addr { return l.pc.LocalAddr() }

// Serve runs the demultiplex loop.
func (l *UDPListener) Serve(ctx context.Context, h Handler) error {
	go func() {
		<-ctx.Done()
		_ = l.pc.Close()
	}()

	go l.reaper(ctx)

	buf := make([]byte, 64<<10)
	for {
		n, addr, err := l.pc.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil || l.closed.Load() {
				l.wg.Wait()
				return nil
			}
			l.log.Warn("udp read failed", "error", err)
			continue
		}

		// Copy: buf is reused on the next iteration.
		dgram := make([]byte, n)
		copy(dgram, buf[:n])
		l.dispatch(ctx, dgram, addr, h)
	}
}

func (l *UDPListener) dispatch(ctx context.Context, dgram []byte, addr *net.UDPAddr, h Handler) {
	hdr, payload, err := parseUDP(dgram)
	if err != nil {
		// Silently ignore garbage: a UDP port receives plenty of it, and
		// logging every stray packet is a denial of service on our own logs.
		return
	}

	l.mu.RLock()
	c, known := l.conns[hdr.connID]
	l.mu.RUnlock()

	if !known {
		if hdr.flags&udpFlagHello == 0 {
			// Unknown connection and not an opening datagram. Dropping is
			// correct: replying would make us a reflection amplifier.
			return
		}
		c = l.newConn(hdr.connID, addr)
		if c == nil {
			return // at capacity
		}
		l.wg.Add(1)
		go func() {
			defer l.wg.Done()
			defer l.remove(hdr.connID)
			h(ctx, c)
		}()
	}

	c.onDatagram(hdr, payload, addr)
}

func (l *UDPListener) newConn(id uint64, addr *net.UDPAddr) *udpConn {
	l.mu.Lock()
	defer l.mu.Unlock()

	if len(l.conns) >= l.MaxConnections {
		l.log.Warn("udp connection refused: pod at capacity", "active", len(l.conns))
		return nil
	}
	if existing, ok := l.conns[id]; ok {
		return existing
	}

	c := &udpConn{
		l:        l,
		id:       id,
		remote:   addr,
		in:       make(chan []byte, 256),
		partials: make(map[uint32]*partial),
		log:      l.log.With("conn_id", id),
	}
	c.idle.Store(int64(defaultIdleTimeout))
	c.lastSeen.Store(time.Now().UnixNano())
	l.conns[id] = c
	return c
}

func (l *UDPListener) remove(id uint64) {
	l.mu.Lock()
	delete(l.conns, id)
	l.mu.Unlock()
}

// reaper drops connections that have gone silent and sweeps stale reassembly
// buffers. Without it a mobile client that vanishes mid-fragment would leak a
// buffer per lost message.
func (l *UDPListener) reaper(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			now := time.Now()
			l.mu.RLock()
			conns := make([]*udpConn, 0, len(l.conns))
			for _, c := range l.conns {
				conns = append(conns, c)
			}
			l.mu.RUnlock()

			for _, c := range conns {
				c.sweepPartials(now)
				idle := time.Duration(c.idle.Load())
				if now.Sub(time.Unix(0, c.lastSeen.Load())) > idle {
					c.log.Debug("udp connection idle, closing")
					_ = c.Close()
				}
			}
		}
	}
}

// Close stops the listener.
func (l *UDPListener) Close() error {
	l.closed.Store(true)
	err := l.pc.Close()
	l.wg.Wait()
	return err
}

// Active reports the number of live logical connections.
func (l *UDPListener) Active() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.conns)
}

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------

// partial is an in-progress reassembly.
type partial struct {
	fragments [][]byte
	received  int
	total     int
	bytes     int
	started   time.Time
}

type udpConn struct {
	l   *UDPListener
	id  uint64
	log *slog.Logger

	remoteMu sync.RWMutex
	remote   *net.UDPAddr

	// pending path validation, if a migration is in flight
	challengeMu   sync.Mutex
	challenge     [8]byte
	challengeAddr *net.UDPAddr
	challengeAt   time.Time

	in       chan []byte
	partials map[uint32]*partial
	partMu   sync.Mutex

	sendSeq  atomic.Uint32
	idle     atomic.Int64
	lastSeen atomic.Int64
	closed   atomic.Bool
	closeOne sync.Once
}

func (c *udpConn) onDatagram(h udpHeader, payload []byte, from *net.UDPAddr) {
	c.lastSeen.Store(time.Now().UnixNano())

	switch {
	case h.flags&udpFlagClose != 0:
		_ = c.Close()
		return

	case h.flags&udpFlagPathResponse != 0:
		c.completeMigration(payload, from)
		return
	}

	// Path validation: a datagram from an unexpected address may be a genuine
	// NAT rebinding or an attacker trying to hijack the connection. We keep
	// serving the old path and challenge the new one; only a correct echo
	// moves us.
	if !c.sameRemote(from) {
		c.beginMigration(from)
		// Fall through: the payload itself is still processed. Accepting the
		// data is safe because the MTProto layer authenticates every frame;
		// what we must not do is *send* to an unvalidated address.
	}

	if h.flags&udpFlagData == 0 {
		return
	}

	// Fast path: a message that fits one datagram needs no reassembly. An
	// empty payload is a keepalive, not a frame, so it is not delivered.
	if h.fragCount == 1 {
		if len(payload) > 0 {
			c.deliver(payload)
		}
		return
	}

	c.partMu.Lock()
	p, ok := c.partials[h.msgSeq]
	if !ok {
		if len(c.partials) >= 64 {
			// Cap concurrent reassemblies per connection: an attacker sending
			// one fragment each of thousands of messages must not pin memory.
			c.partMu.Unlock()
			return
		}
		p = &partial{
			fragments: make([][]byte, h.fragCount),
			total:     int(h.fragCount),
			started:   time.Now(),
		}
		c.partials[h.msgSeq] = p
	}
	if p.total != int(h.fragCount) || int(h.fragIndex) >= p.total {
		c.partMu.Unlock()
		return
	}
	if p.fragments[h.fragIndex] == nil {
		p.fragments[h.fragIndex] = payload
		p.received++
		p.bytes += len(payload)
	}
	complete := p.received == p.total
	tooBig := p.bytes > maxFrameSize
	if complete || tooBig {
		delete(c.partials, h.msgSeq)
	}
	c.partMu.Unlock()

	if tooBig {
		c.log.Warn("dropping oversized reassembly", "bytes", p.bytes)
		return
	}
	if !complete {
		return
	}

	full := make([]byte, 0, p.bytes)
	for _, f := range p.fragments {
		full = append(full, f...)
	}
	c.deliver(full)
}

func (c *udpConn) deliver(frame []byte) {
	select {
	case c.in <- frame:
	default:
		// The session loop is behind. Dropping is the right call for UDP:
		// blocking the demux goroutine would stall every other connection on
		// this pod, and the MTProto layer will retransmit.
		c.log.Warn("udp inbound queue full, frame dropped")
	}
}

func (c *udpConn) sameRemote(a *net.UDPAddr) bool {
	c.remoteMu.RLock()
	defer c.remoteMu.RUnlock()
	return c.remote.IP.Equal(a.IP) && c.remote.Port == a.Port
}

// beginMigration challenges a candidate address.
func (c *udpConn) beginMigration(to *net.UDPAddr) {
	c.challengeMu.Lock()
	// Rate-limit challenges so a spoofed source cannot make us emit a flood.
	if time.Since(c.challengeAt) < time.Second {
		c.challengeMu.Unlock()
		return
	}
	if _, err := rand.Read(c.challenge[:]); err != nil {
		c.challengeMu.Unlock()
		return
	}
	token := c.challenge
	c.challengeAddr = to
	c.challengeAt = time.Now()
	c.challengeMu.Unlock()

	hdr := udpHeader{flags: udpFlagPathChallenge, connID: c.id, fragCount: 1}
	if _, err := c.l.pc.WriteToUDP(hdr.marshal(token[:]), to); err != nil {
		c.log.Debug("path challenge failed", "error", err)
	}
}

// completeMigration moves the connection if the echo matches.
func (c *udpConn) completeMigration(payload []byte, from *net.UDPAddr) {
	c.challengeMu.Lock()
	defer c.challengeMu.Unlock()

	if c.challengeAddr == nil || time.Since(c.challengeAt) > 5*time.Second {
		return
	}
	if !c.challengeAddr.IP.Equal(from.IP) || c.challengeAddr.Port != from.Port {
		return
	}
	if subtle.ConstantTimeCompare(payload, c.challenge[:]) != 1 {
		return
	}

	c.remoteMu.Lock()
	old := c.remote
	c.remote = from
	c.remoteMu.Unlock()

	c.challengeAddr = nil
	c.log.Info("udp path migrated", "from", old.String(), "to", from.String())
}

func (c *udpConn) sweepPartials(now time.Time) {
	c.partMu.Lock()
	defer c.partMu.Unlock()
	for seq, p := range c.partials {
		if now.Sub(p.started) > udpReassemblyTTL {
			delete(c.partials, seq)
		}
	}
}

func (c *udpConn) ReadFrame(ctx context.Context) ([]byte, error) {
	if c.closed.Load() {
		return nil, ErrClosed
	}
	idle := time.Duration(c.idle.Load())
	timer := time.NewTimer(idle)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case f, ok := <-c.in:
		if !ok {
			return nil, ErrClosed
		}
		return f, nil
	case <-timer.C:
		return nil, ErrTimeout
	}
}

func (c *udpConn) WriteFrame(ctx context.Context, frame []byte) error {
	if c.closed.Load() {
		return ErrClosed
	}
	if len(frame) > maxFrameSize {
		return fmt.Errorf("transport: frame of %d bytes exceeds the limit", len(frame))
	}

	c.remoteMu.RLock()
	remote := c.remote
	c.remoteMu.RUnlock()

	seq := c.sendSeq.Add(1)
	total := (len(frame) + udpMaxPayload - 1) / udpMaxPayload
	if total == 0 {
		total = 1
	}
	if total > udpMaxFragments {
		return fmt.Errorf("transport: frame needs %d fragments, limit is %d", total, udpMaxFragments)
	}

	for i := 0; i < total; i++ {
		start := i * udpMaxPayload
		end := start + udpMaxPayload
		if end > len(frame) {
			end = len(frame)
		}
		hdr := udpHeader{
			flags:     udpFlagData,
			connID:    c.id,
			msgSeq:    seq,
			fragIndex: uint16(i),
			fragCount: uint16(total),
		}
		if _, err := c.l.pc.WriteToUDP(hdr.marshal(frame[start:end]), remote); err != nil {
			return fmt.Errorf("transport: udp write: %w", err)
		}
	}
	return nil
}

func (c *udpConn) Close() error {
	c.closeOne.Do(func() {
		c.closed.Store(true)
		close(c.in)

		c.remoteMu.RLock()
		remote := c.remote
		c.remoteMu.RUnlock()

		hdr := udpHeader{flags: udpFlagClose, connID: c.id, fragCount: 1}
		_, _ = c.l.pc.WriteToUDP(hdr.marshal(nil), remote)
		c.l.remove(c.id)
	})
	return nil
}

func (c *udpConn) RemoteAddr() net.Addr {
	c.remoteMu.RLock()
	defer c.remoteMu.RUnlock()
	return c.remote
}

func (c *udpConn) Kind() Kind      { return KindUDP }
func (c *udpConn) Framing() string { return "udp_datagram" }

func (c *udpConn) SetIdleTimeout(d time.Duration) {
	if d > 0 {
		c.idle.Store(int64(d))
	}
}

// DialUDP opens a client-side UDP connection. Used by the load generator and
// the end-to-end tests.
func DialUDP(ctx context.Context, addr string) (*UDPClient, error) {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("transport: resolve %s: %w", addr, err)
	}
	pc, err := net.DialUDP("udp", nil, ua)
	if err != nil {
		return nil, fmt.Errorf("transport: dial udp %s: %w", addr, err)
	}

	var idBytes [8]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return nil, err
	}

	c := &UDPClient{
		pc:       pc,
		id:       binary.BigEndian.Uint64(idBytes[:]),
		partials: make(map[uint32]*partial),
		in:       make(chan []byte, 64),
	}
	go c.readLoop()

	// The opening datagram carries only the hello flag so the server creates
	// state. A client with data ready may set udpFlagData alongside it and
	// save a round trip; an empty hello never becomes a delivered frame.
	hdr := udpHeader{flags: udpFlagHello, connID: c.id, fragCount: 1}
	if _, err := pc.Write(hdr.marshal(nil)); err != nil {
		_ = pc.Close()
		return nil, fmt.Errorf("transport: udp hello: %w", err)
	}
	return c, nil
}

// UDPClient is the client half of the UDP transport.
type UDPClient struct {
	pc       *net.UDPConn
	id       uint64
	sendSeq  atomic.Uint32
	in       chan []byte
	partials map[uint32]*partial
	partMu   sync.Mutex
	closed   atomic.Bool
	closeOne sync.Once
}

func (c *UDPClient) readLoop() {
	buf := make([]byte, 64<<10)
	for {
		n, err := c.pc.Read(buf)
		if err != nil {
			c.closeOne.Do(func() { c.closed.Store(true); close(c.in) })
			return
		}
		hdr, payload, err := parseUDP(buf[:n])
		if err != nil {
			continue
		}

		// Answer path challenges so the server can validate a new address
		// after the client's NAT rebinds.
		if hdr.flags&udpFlagPathChallenge != 0 {
			resp := udpHeader{flags: udpFlagPathResponse, connID: c.id, fragCount: 1}
			_, _ = c.pc.Write(resp.marshal(payload))
			continue
		}
		if hdr.flags&udpFlagClose != 0 {
			c.closeOne.Do(func() { c.closed.Store(true); close(c.in) })
			return
		}
		if hdr.flags&udpFlagData == 0 {
			continue
		}

		frag := make([]byte, len(payload))
		copy(frag, payload)

		if hdr.fragCount == 1 {
			select {
			case c.in <- frag:
			default:
			}
			continue
		}

		c.partMu.Lock()
		p, ok := c.partials[hdr.msgSeq]
		if !ok {
			p = &partial{fragments: make([][]byte, hdr.fragCount), total: int(hdr.fragCount), started: time.Now()}
			c.partials[hdr.msgSeq] = p
		}
		if int(hdr.fragIndex) < p.total && p.fragments[hdr.fragIndex] == nil {
			p.fragments[hdr.fragIndex] = frag
			p.received++
			p.bytes += len(frag)
		}
		complete := p.received == p.total
		if complete {
			delete(c.partials, hdr.msgSeq)
		}
		c.partMu.Unlock()

		if complete {
			full := make([]byte, 0, p.bytes)
			for _, f := range p.fragments {
				full = append(full, f...)
			}
			select {
			case c.in <- full:
			default:
			}
		}
	}
}

// WriteFrame sends a frame, fragmenting as needed.
func (c *UDPClient) WriteFrame(_ context.Context, frame []byte) error {
	if c.closed.Load() {
		return ErrClosed
	}
	seq := c.sendSeq.Add(1)
	total := (len(frame) + udpMaxPayload - 1) / udpMaxPayload
	if total == 0 {
		total = 1
	}
	for i := 0; i < total; i++ {
		start := i * udpMaxPayload
		end := start + udpMaxPayload
		if end > len(frame) {
			end = len(frame)
		}
		hdr := udpHeader{
			flags: udpFlagData, connID: c.id, msgSeq: seq,
			fragIndex: uint16(i), fragCount: uint16(total),
		}
		if _, err := c.pc.Write(hdr.marshal(frame[start:end])); err != nil {
			return err
		}
	}
	return nil
}

// ReadFrame returns the next reassembled frame.
func (c *UDPClient) ReadFrame(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case f, ok := <-c.in:
		if !ok {
			return nil, ErrClosed
		}
		return f, nil
	}
}

// Close tears the client connection down.
func (c *UDPClient) Close() error {
	hdr := udpHeader{flags: udpFlagClose, connID: c.id, fragCount: 1}
	_, _ = c.pc.Write(hdr.marshal(nil))
	return c.pc.Close()
}

// RemoteAddr returns the server address.
func (c *UDPClient) RemoteAddr() net.Addr { return c.pc.RemoteAddr() }

// Kind reports the transport.
func (c *UDPClient) Kind() Kind { return KindUDP }

// Framing reports the codec.
func (c *UDPClient) Framing() string { return "udp_datagram" }

// SetIdleTimeout is a no-op on the client side.
func (c *UDPClient) SetIdleTimeout(time.Duration) {}
