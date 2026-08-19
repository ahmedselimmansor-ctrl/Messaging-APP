// Package codec implements MTProto's transport framings.
//
// A framing answers one question: where does a message end? MTProto defines
// several because they trade bytes against features:
//
//	abridged             1 or 4 byte header. Smallest on the wire; what a
//	                     mobile client uses by default.
//	intermediate         4 byte little-endian length. Byte-aligned, which
//	                     matters when an obfuscation layer sits underneath.
//	padded intermediate  intermediate plus 0..15 random bytes, so packet
//	                     lengths stop being a fingerprint for traffic analysis.
//	full                 length, sequence number and CRC32. The only framing
//	                     that detects corruption itself, used where the
//	                     underlying transport is not trusted.
//
// The client picks one by sending a magic prefix as the first bytes of the
// connection; the server detects it and answers in kind.
package codec

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math/rand"
)

// MaxFrameSize bounds a single frame. Anything larger is refused before we
// allocate, so a hostile length header cannot exhaust the pod's memory.
const MaxFrameSize = 16 << 20 // 16 MiB

// Errors.
var (
	ErrFrameTooLarge = errors.New("codec: frame exceeds the maximum size")
	ErrBadCRC        = errors.New("codec: CRC32 mismatch")
	ErrBadSeqNo      = errors.New("codec: transport sequence number out of order")
	ErrUnknownMagic  = errors.New("codec: unrecognised transport magic")
	ErrQuickAck      = errors.New("codec: quick-ack frames are not supported")
)

// Transport magic prefixes.
const (
	magicAbridged           byte   = 0xef
	magicIntermediate       uint32 = 0xeeeeeeee
	magicPaddedIntermediate uint32 = 0xdddddddd
	magicFull               uint32 = 0x00000000 // full framing has no prefix
)

// Codec reads and writes framed payloads.
//
// Implementations are stateful (the full codec tracks sequence numbers) and
// therefore not safe for concurrent use; each connection owns one, and the
// connection serialises writes through a single writer goroutine.
type Codec interface {
	// ReadFrame returns the next payload.
	ReadFrame(r *bufio.Reader) ([]byte, error)
	// WriteFrame writes one payload.
	WriteFrame(w io.Writer, payload []byte) error
	// Name identifies the framing in logs and metrics.
	Name() string
}

// Detect reads the transport prefix and returns the matching codec.
//
// It must be called once, on the first bytes of a connection, before any
// frame is read.
func Detect(r *bufio.Reader) (Codec, error) {
	first, err := r.Peek(1)
	if err != nil {
		return nil, fmt.Errorf("codec: peek transport magic: %w", err)
	}

	if first[0] == magicAbridged {
		if _, err := r.Discard(1); err != nil {
			return nil, err
		}
		return &Abridged{}, nil
	}

	head, err := r.Peek(4)
	if err != nil {
		return nil, fmt.Errorf("codec: peek transport magic: %w", err)
	}
	switch binary.LittleEndian.Uint32(head) {
	case magicIntermediate:
		if _, err := r.Discard(4); err != nil {
			return nil, err
		}
		return &Intermediate{}, nil
	case magicPaddedIntermediate:
		if _, err := r.Discard(4); err != nil {
			return nil, err
		}
		return &PaddedIntermediate{}, nil
	}

	// No recognised prefix: assume full framing, which starts straight in
	// with a length field.
	return &Full{}, nil
}

// ByName returns a codec by its short name, for configuration and tests.
func ByName(name string) (Codec, error) {
	switch name {
	case "abridged":
		return &Abridged{}, nil
	case "intermediate":
		return &Intermediate{}, nil
	case "padded", "padded_intermediate":
		return &PaddedIntermediate{}, nil
	case "full":
		return &Full{}, nil
	}
	return nil, fmt.Errorf("%w: %q", ErrUnknownMagic, name)
}

// ---------------------------------------------------------------------------
// Abridged
// ---------------------------------------------------------------------------

// Abridged is MTProto's smallest framing.
//
// Length is expressed in 4-byte words: one byte when the payload is under 508
// bytes, otherwise 0x7f followed by a 3-byte little-endian word count. Since
// almost every chat message fits the one-byte form, this saves three bytes per
// frame against intermediate — which is negligible on a desktop and material
// on a metered mobile connection sending thousands of messages a day.
type Abridged struct{}

func (*Abridged) Name() string { return "abridged" }

func (*Abridged) ReadFrame(r *bufio.Reader) ([]byte, error) {
	b, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	// The high bit marks a quick-ack response, which this server does not
	// implement; rejecting explicitly beats mis-parsing the stream.
	if b&0x80 != 0 {
		return nil, ErrQuickAck
	}

	var words uint32
	if b < 0x7f {
		words = uint32(b)
	} else {
		var ext [3]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return nil, err
		}
		words = uint32(ext[0]) | uint32(ext[1])<<8 | uint32(ext[2])<<16
	}

	n := int(words) * 4
	if n <= 0 || n > MaxFrameSize {
		return nil, fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, n)
	}

	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func (*Abridged) WriteFrame(w io.Writer, payload []byte) error {
	if len(payload) > MaxFrameSize {
		return fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, len(payload))
	}

	// Abridged expresses length in 4-byte words, so a payload that is not
	// word-aligned cannot be represented. Padding here rather than rejecting
	// is the right call: alignment is a property of this framing, and making
	// every caller remember it is a footgun that produces an unsent frame and
	// a bare EOF at the other end.
	//
	// Nothing is lost. An MTProto envelope is always 16-byte aligned, so this
	// only ever fires for a plain handshake frame — and those carry an
	// explicit length field, so the reader ignores the padding.
	if r := len(payload) % 4; r != 0 {
		padded := make([]byte, len(payload)+4-r)
		copy(padded, payload)
		payload = padded
	}

	words := len(payload) / 4
	var header []byte
	if words < 0x7f {
		header = []byte{byte(words)}
	} else {
		header = []byte{0x7f, byte(words), byte(words >> 8), byte(words >> 16)}
	}

	if _, err := w.Write(header); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// ---------------------------------------------------------------------------
// Intermediate
// ---------------------------------------------------------------------------

// Intermediate prefixes each payload with a 4-byte little-endian length.
type Intermediate struct{}

func (*Intermediate) Name() string { return "intermediate" }

func (*Intermediate) ReadFrame(r *bufio.Reader) ([]byte, error) {
	var head [4]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, err
	}
	n := binary.LittleEndian.Uint32(head[:])
	if n&0x80000000 != 0 {
		return nil, ErrQuickAck
	}
	if n == 0 || n > MaxFrameSize {
		return nil, fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, n)
	}

	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func (*Intermediate) WriteFrame(w io.Writer, payload []byte) error {
	if len(payload) > MaxFrameSize {
		return fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, len(payload))
	}
	var head [4]byte
	binary.LittleEndian.PutUint32(head[:], uint32(len(payload)))
	if _, err := w.Write(head[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// ---------------------------------------------------------------------------
// Padded intermediate
// ---------------------------------------------------------------------------

// maxIntermediatePad is the largest padding a padded-intermediate frame adds.
const maxIntermediatePad = 16

// PaddedIntermediate appends 1..16 random bytes to every frame.
//
// The MTProto envelope already pads to hide the exact body size; this pads the
// *packet* so an observer counting bytes on the wire cannot fingerprint
// message sizes either. It costs eight bytes on average and defeats a whole
// class of traffic analysis, which is why it is the default for connections
// that go through the obfuscation layer.
//
// Deviation from Telegram's "dd" framing: the final byte of the frame holds
// the padding length, PKCS#7-style, and padding is 1..16 rather than 0..15.
// Telegram's variant leaves the receiver to infer the boundary from the
// MTProto envelope it wraps, which couples the framing to its payload; making
// the length explicit costs one byte and keeps the codec independent of what
// it carries.
type PaddedIntermediate struct{}

func (*PaddedIntermediate) Name() string { return "padded_intermediate" }

func (*PaddedIntermediate) ReadFrame(r *bufio.Reader) ([]byte, error) {
	var head [4]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, err
	}
	n := binary.LittleEndian.Uint32(head[:])
	if n == 0 || n > MaxFrameSize {
		return nil, fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, n)
	}

	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}

	pad := int(buf[len(buf)-1])
	if pad < 1 || pad > maxIntermediatePad || pad > len(buf) {
		return nil, fmt.Errorf("codec: padded frame declares %d padding bytes in %d total", pad, len(buf))
	}
	return buf[:len(buf)-pad], nil
}

func (*PaddedIntermediate) WriteFrame(w io.Writer, payload []byte) error {
	//nolint:gosec // Padding only needs to be unpredictable to an observer
	// counting bytes; it carries no secret, and a CSPRNG call per frame would
	// be pure overhead on the hot path.
	pad := 1 + rand.Intn(maxIntermediatePad)
	total := len(payload) + pad
	if total > MaxFrameSize {
		return fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, total)
	}

	var head [4]byte
	binary.LittleEndian.PutUint32(head[:], uint32(total))
	if _, err := w.Write(head[:]); err != nil {
		return err
	}
	if _, err := w.Write(payload); err != nil {
		return err
	}

	padding := make([]byte, pad)
	//nolint:gosec // see above
	for i := range padding {
		padding[i] = byte(rand.Intn(256))
	}
	padding[pad-1] = byte(pad)
	_, err := w.Write(padding)
	return err
}

// ---------------------------------------------------------------------------
// Full
// ---------------------------------------------------------------------------

// Full carries a length, a transport sequence number and a CRC32.
//
// Layout: len(4) ‖ seq_no(4) ‖ payload ‖ crc32(4), where len covers the whole
// frame including itself and the checksum.
//
// It is the only framing that can detect a truncated or reordered stream on
// its own, which is why the UDP transport wraps it: UDP gives no ordering or
// integrity guarantee of its own.
type Full struct {
	recvSeq uint32
	sendSeq uint32
}

func (*Full) Name() string { return "full" }

func (c *Full) ReadFrame(r *bufio.Reader) ([]byte, error) {
	var head [8]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, err
	}
	total := binary.LittleEndian.Uint32(head[0:4])
	seq := binary.LittleEndian.Uint32(head[4:8])

	if total < 12 || total > MaxFrameSize {
		return nil, fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, total)
	}
	if seq != c.recvSeq {
		return nil, fmt.Errorf("%w: got %d, expected %d", ErrBadSeqNo, seq, c.recvSeq)
	}

	bodyLen := int(total) - 12
	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	var checksum [4]byte
	if _, err := io.ReadFull(r, checksum[:]); err != nil {
		return nil, err
	}

	crc := crc32.NewIEEE()
	_, _ = crc.Write(head[:])
	_, _ = crc.Write(body)
	if got := crc.Sum32(); got != binary.LittleEndian.Uint32(checksum[:]) {
		return nil, fmt.Errorf("%w: computed %08x, frame carried %08x",
			ErrBadCRC, got, binary.LittleEndian.Uint32(checksum[:]))
	}

	c.recvSeq++
	return body, nil
}

func (c *Full) WriteFrame(w io.Writer, payload []byte) error {
	total := len(payload) + 12
	if total > MaxFrameSize {
		return fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, total)
	}

	frame := make([]byte, 0, total)
	var head [8]byte
	binary.LittleEndian.PutUint32(head[0:4], uint32(total))
	binary.LittleEndian.PutUint32(head[4:8], c.sendSeq)
	frame = append(frame, head[:]...)
	frame = append(frame, payload...)

	crc := crc32.ChecksumIEEE(frame)
	var checksum [4]byte
	binary.LittleEndian.PutUint32(checksum[:], crc)
	frame = append(frame, checksum[:]...)

	if _, err := w.Write(frame); err != nil {
		return err
	}
	c.sendSeq++
	return nil
}

// WriteMagic emits the prefix a client sends to select a framing. Used by the
// load generator and the reference client.
func WriteMagic(w io.Writer, c Codec) error {
	switch c.(type) {
	case *Abridged:
		_, err := w.Write([]byte{magicAbridged})
		return err
	case *Intermediate:
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], magicIntermediate)
		_, err := w.Write(b[:])
		return err
	case *PaddedIntermediate:
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], magicPaddedIntermediate)
		_, err := w.Write(b[:])
		return err
	case *Full:
		return nil // no prefix
	}
	return fmt.Errorf("codec: cannot write magic for %T", c)
}

// PadTo4 right-pads a payload to a 4-byte boundary.
//
// The abridged codec now does this itself, so callers no longer need it; it
// remains for a client that wants to control its own framing explicitly.
func PadTo4(b []byte) []byte {
	if r := len(b) % 4; r != 0 {
		return append(b, make([]byte, 4-r)...)
	}
	return b
}
