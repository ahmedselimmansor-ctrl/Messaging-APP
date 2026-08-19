package mediaproc

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// Virus scanning.
//
// A messaging platform is a file transfer service that happens to have chat
// attached, and an unscanned one becomes a malware distribution network within
// weeks of being popular. Scanning is not optional.
//
// The Scanner interface has two implementations: clamd over TCP, and a no-op
// for development. A commercial engine would be a third; nothing above this
// interface would change.

// ScanResult is the verdict on one object.
type ScanResult struct {
	Clean bool
	// Threat is the signature name when Clean is false.
	Threat string
}

// Scanner inspects an object's bytes.
type Scanner interface {
	Scan(ctx context.Context, r io.Reader, size int64) (ScanResult, error)
	Name() string
}

// ErrScanUnavailable means the scanner could not be reached.
//
// It is distinct from "the file is infected" on purpose: an unavailable
// scanner must fail the job and retry, never silently pass the file through.
var ErrScanUnavailable = errors.New("mediaproc: scanner unavailable")

// ---------------------------------------------------------------------------
// ClamAV
// ---------------------------------------------------------------------------

// ClamAV speaks clamd's INSTREAM protocol directly.
//
// Directly, rather than through a library: the protocol is a length-prefixed
// stream and a terminating zero-length chunk, which is thirty lines here
// against a dependency that would have to be kept current in the one service
// that handles hostile input.
type ClamAV struct {
	// Addr is the clamd address, typically a sidecar at 127.0.0.1:3310.
	Addr string
	// Timeout bounds one scan. A large file legitimately takes seconds.
	Timeout time.Duration
	// MaxBytes must not exceed clamd's own StreamMaxLength, or clamd closes
	// the connection mid-stream and the error is opaque.
	MaxBytes int64
	// ChunkSize is the INSTREAM chunk. 64KB balances syscall count against
	// memory.
	ChunkSize int
}

// NewClamAV builds a scanner.
func NewClamAV(addr string) *ClamAV {
	return &ClamAV{
		Addr:      addr,
		Timeout:   120 * time.Second,
		MaxBytes:  256 << 20,
		ChunkSize: 64 << 10,
	}
}

func (c *ClamAV) Name() string { return "clamav" }

// Ping checks clamd is alive; used as a readiness check.
func (c *ClamAV) Ping(ctx context.Context) error {
	conn, err := c.dial(ctx, 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("zPING\x00")); err != nil {
		return fmt.Errorf("%w: write PING: %v", ErrScanUnavailable, err)
	}
	buf := make([]byte, 32)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("%w: read PONG: %v", ErrScanUnavailable, err)
	}
	if !strings.HasPrefix(string(buf[:n]), "PONG") {
		return fmt.Errorf("%w: unexpected reply %q", ErrScanUnavailable, string(buf[:n]))
	}
	return nil
}

func (c *ClamAV) dial(ctx context.Context, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", c.Addr)
	if err != nil {
		return nil, fmt.Errorf("%w: dial %s: %v", ErrScanUnavailable, c.Addr, err)
	}
	return conn, nil
}

// Scan streams the object to clamd and returns its verdict.
//
// INSTREAM: send "zINSTREAM\0", then a sequence of
// [4-byte big-endian length][data] chunks, then a zero length to end the
// stream. clamd replies with "stream: OK" or "stream: <signature> FOUND".
func (c *ClamAV) Scan(ctx context.Context, r io.Reader, size int64) (ScanResult, error) {
	if c.MaxBytes > 0 && size > c.MaxBytes {
		// Refusing rather than skipping. A file too large to scan is a file
		// that must not be served, or the size limit becomes the bypass.
		return ScanResult{}, fmt.Errorf(
			"mediaproc: object of %d bytes exceeds the %d byte scan limit", size, c.MaxBytes)
	}

	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := c.dial(ctx, 10*time.Second)
	if err != nil {
		return ScanResult{}, err
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	if _, err := conn.Write([]byte("zINSTREAM\x00")); err != nil {
		return ScanResult{}, fmt.Errorf("%w: write INSTREAM: %v", ErrScanUnavailable, err)
	}

	chunkSize := c.ChunkSize
	if chunkSize <= 0 {
		chunkSize = 64 << 10
	}
	buf := make([]byte, chunkSize)
	var header [4]byte

	for {
		n, readErr := r.Read(buf)
		if n > 0 {
			binary.BigEndian.PutUint32(header[:], uint32(n))
			if _, err := conn.Write(header[:]); err != nil {
				return ScanResult{}, fmt.Errorf("%w: write chunk header: %v", ErrScanUnavailable, err)
			}
			if _, err := conn.Write(buf[:n]); err != nil {
				return ScanResult{}, fmt.Errorf("%w: write chunk: %v", ErrScanUnavailable, err)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return ScanResult{}, fmt.Errorf("mediaproc: read object: %w", readErr)
		}
	}

	// A zero-length chunk terminates the stream.
	binary.BigEndian.PutUint32(header[:], 0)
	if _, err := conn.Write(header[:]); err != nil {
		return ScanResult{}, fmt.Errorf("%w: write terminator: %v", ErrScanUnavailable, err)
	}

	reply := make([]byte, 512)
	n, err := conn.Read(reply)
	if err != nil && err != io.EOF {
		return ScanResult{}, fmt.Errorf("%w: read verdict: %v", ErrScanUnavailable, err)
	}
	verdict := strings.TrimRight(string(reply[:n]), "\x00\n ")

	switch {
	case strings.HasSuffix(verdict, "OK"):
		return ScanResult{Clean: true}, nil

	case strings.HasSuffix(verdict, "FOUND"):
		// "stream: Eicar-Test-Signature FOUND"
		threat := verdict
		if i := strings.Index(verdict, ": "); i >= 0 {
			threat = strings.TrimSuffix(verdict[i+2:], " FOUND")
		}
		return ScanResult{Clean: false, Threat: threat}, nil

	case strings.Contains(verdict, "ERROR"):
		// Includes "INSTREAM size limit exceeded", which means clamd's own
		// StreamMaxLength is below our MaxBytes.
		return ScanResult{}, fmt.Errorf("%w: clamd reported %q", ErrScanUnavailable, verdict)
	}

	return ScanResult{}, fmt.Errorf("%w: unrecognised verdict %q", ErrScanUnavailable, verdict)
}

// ---------------------------------------------------------------------------
// No-op
// ---------------------------------------------------------------------------

// NoopScanner passes everything. Development only — the consumer refuses to
// start with it when ENV=prod, because a silently disabled scanner is worse
// than none at all.
type NoopScanner struct{}

func (NoopScanner) Name() string { return "noop" }

func (NoopScanner) Scan(context.Context, io.Reader, int64) (ScanResult, error) {
	return ScanResult{Clean: true}, nil
}
