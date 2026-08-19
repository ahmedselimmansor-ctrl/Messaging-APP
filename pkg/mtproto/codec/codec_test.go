package codec

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestFramingRoundTrip(t *testing.T) {
	payloads := [][]byte{
		bytes.Repeat([]byte{0xAA}, 4),
		bytes.Repeat([]byte{0xBB}, 64),
		bytes.Repeat([]byte{0xCC}, 512),
		bytes.Repeat([]byte{0xDD}, 4096),
		// Cross the abridged one-byte/four-byte length boundary (127 words).
		bytes.Repeat([]byte{0xEE}, 127*4),
		bytes.Repeat([]byte{0xFF}, 128*4),
	}

	for _, name := range []string{"abridged", "intermediate", "padded", "full"} {
		t.Run(name, func(t *testing.T) {
			writeCodec, err := ByName(name)
			if err != nil {
				t.Fatalf("by name: %v", err)
			}
			readCodec, _ := ByName(name)

			var buf bytes.Buffer
			for _, p := range payloads {
				if err := writeCodec.WriteFrame(&buf, p); err != nil {
					t.Fatalf("write %d bytes: %v", len(p), err)
				}
			}

			r := bufio.NewReader(&buf)
			for i, want := range payloads {
				got, err := readCodec.ReadFrame(r)
				if err != nil {
					t.Fatalf("frame %d: read: %v", i, err)
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("frame %d: got %d bytes, want %d", i, len(got), len(want))
				}
			}
			if _, err := readCodec.ReadFrame(r); !errors.Is(err, io.EOF) {
				t.Fatalf("expected EOF after the last frame, got %v", err)
			}
		})
	}
}

func TestDetect(t *testing.T) {
	cases := map[string]string{
		"abridged":     "abridged",
		"intermediate": "intermediate",
		"padded":       "padded_intermediate",
	}
	for name, wantName := range cases {
		c, _ := ByName(name)
		var buf bytes.Buffer
		if err := WriteMagic(&buf, c); err != nil {
			t.Fatalf("%s: write magic: %v", name, err)
		}
		if err := c.WriteFrame(&buf, bytes.Repeat([]byte{1}, 16)); err != nil {
			t.Fatalf("%s: write frame: %v", name, err)
		}

		r := bufio.NewReader(&buf)
		got, err := Detect(r)
		if err != nil {
			t.Fatalf("%s: detect: %v", name, err)
		}
		if got.Name() != wantName {
			t.Fatalf("detect %s = %s, want %s", name, got.Name(), wantName)
		}
		if _, err := got.ReadFrame(r); err != nil {
			t.Fatalf("%s: read after detect: %v", name, err)
		}
	}
}

func TestFullRejectsCorruption(t *testing.T) {
	c := &Full{}
	var buf bytes.Buffer
	payload := bytes.Repeat([]byte{0x5A}, 32)
	if err := c.WriteFrame(&buf, payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	corrupted := buf.Bytes()
	corrupted[12] ^= 0xFF // flip a payload byte, leaving the CRC stale

	reader := &Full{}
	if _, err := reader.ReadFrame(bufio.NewReader(bytes.NewReader(corrupted))); !errors.Is(err, ErrBadCRC) {
		t.Fatalf("corrupted frame: got %v, want ErrBadCRC", err)
	}
}

func TestFullRejectsReorder(t *testing.T) {
	w := &Full{}
	var buf bytes.Buffer
	_ = w.WriteFrame(&buf, []byte("first-frame-pad!"))
	var second bytes.Buffer
	_ = w.WriteFrame(&second, []byte("second-frame-pd!"))

	// Feed the reader the second frame first: its sequence number is 1 where
	// the reader expects 0.
	r := &Full{}
	if _, err := r.ReadFrame(bufio.NewReader(bytes.NewReader(second.Bytes()))); !errors.Is(err, ErrBadSeqNo) {
		t.Fatalf("out-of-order frame: got %v, want ErrBadSeqNo", err)
	}
}

func TestOversizeFrameRejected(t *testing.T) {
	// A hostile 4-byte length header claiming 3.5 GiB must be refused before
	// any allocation happens.
	head := []byte{0xFF, 0xFF, 0xFF, 0x7F}
	c := &Intermediate{}
	if _, err := c.ReadFrame(bufio.NewReader(bytes.NewReader(head))); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("oversize length: got %v, want ErrFrameTooLarge", err)
	}
}

// TestObfuscationRoundTrip runs a real client/server pair over a socket pair
// and checks the framing survives the CTR layer in both directions.
func TestObfuscationRoundTrip(t *testing.T) {
	for _, framingName := range []string{"abridged", "intermediate", "padded"} {
		t.Run(framingName, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			t.Cleanup(func() { _ = clientConn.Close(); _ = serverConn.Close() })

			framing, _ := ByName(framingName)
			payload := bytes.Repeat([]byte{0x42}, 64)
			reply := bytes.Repeat([]byte{0x24}, 32)

			var wg sync.WaitGroup
			var serverErr error
			var gotPayload []byte

			wg.Add(1)
			go func() {
				defer wg.Done()
				br := bufio.NewReader(serverConn)
				oc, err := AcceptObfuscated(serverConn, br)
				if err != nil {
					serverErr = err
					return
				}
				if oc.Codec.Name() != framing.Name() {
					serverErr = errors.New("framing mismatch: " + oc.Codec.Name())
					return
				}
				// Reads must come through the obfuscated wrapper, but the
				// buffered reader already holds bytes from the socket, so the
				// server reads from a reader layered on the wrapper.
				r := bufio.NewReader(oc)
				gotPayload, serverErr = oc.Codec.ReadFrame(r)
				if serverErr != nil {
					return
				}
				serverErr = oc.Codec.WriteFrame(oc, reply)
			}()

			oc, err := DialObfuscated(clientConn, framing, 1)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			if err := oc.Codec.WriteFrame(oc, payload); err != nil {
				t.Fatalf("client write: %v", err)
			}

			cr := bufio.NewReader(oc)
			gotReply, err := oc.Codec.ReadFrame(cr)
			if err != nil {
				t.Fatalf("client read: %v", err)
			}

			wg.Wait()
			if serverErr != nil {
				t.Fatalf("server: %v", serverErr)
			}
			if !bytes.Equal(gotPayload, payload) {
				t.Fatalf("server received %d bytes, want %d", len(gotPayload), len(payload))
			}
			if !bytes.Equal(gotReply, reply) {
				t.Fatalf("client received %d bytes, want %d", len(gotReply), len(reply))
			}
		})
	}
}

func TestObfuscatedInitIsNotRecognisable(t *testing.T) {
	// The init packet must never begin with a byte or word another framing
	// would claim, or a DPI box could classify the connection immediately.
	for i := 0; i < 200; i++ {
		clientConn, serverConn := net.Pipe()
		framing, _ := ByName("intermediate")

		captured := make([]byte, initPacketSize)
		done := make(chan error, 1)
		go func() {
			_, err := io.ReadFull(serverConn, captured)
			done <- err
		}()

		if _, err := DialObfuscated(clientConn, framing, 2); err != nil {
			t.Fatalf("dial: %v", err)
		}
		if err := <-done; err != nil {
			t.Fatalf("read init: %v", err)
		}
		_ = clientConn.Close()
		_ = serverConn.Close()

		if captured[0] == magicAbridged || captured[0] == 0x00 {
			t.Fatalf("init packet starts with a reserved byte %#x", captured[0])
		}
	}
}

// TestObfuscatedInitCoalescedWithFirstFrame is a regression test.
//
// TCP is free to deliver the client's 64-byte init packet and its first frame
// in one segment. AcceptObfuscated reads the init through a bufio.Reader, so
// that reader ends up holding the frame bytes too; an implementation that
// then reads from the raw connection instead of the buffer silently loses the
// first frame — intermittently, and only under the right timing.
//
// Writing both parts in a single Write makes the coalescing certain.
func TestObfuscatedInitCoalescedWithFirstFrame(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { _ = clientConn.Close(); _ = serverConn.Close() })

	framing, _ := ByName("intermediate")
	payload := bytes.Repeat([]byte{0x77}, 96)

	type result struct {
		frame []byte
		err   error
	}
	done := make(chan result, 1)

	go func() {
		br := bufio.NewReaderSize(serverConn, 16<<10)
		oc, err := AcceptObfuscated(serverConn, br)
		if err != nil {
			done <- result{err: err}
			return
		}
		frame, err := oc.Codec.ReadFrame(bufio.NewReader(oc))
		done <- result{frame: frame, err: err}
	}()

	// Build the init packet and the first frame, then put them on the wire as
	// one write.
	var wire bytes.Buffer
	oc, err := DialObfuscated(&captureConn{Writer: &wire, Conn: clientConn}, framing, 1)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if err := oc.Codec.WriteFrame(oc, payload); err != nil {
		t.Fatalf("write frame: %v", err)
	}

	go func() { _, _ = clientConn.Write(wire.Bytes()) }()

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("server: %v", r.err)
		}
		if !bytes.Equal(r.frame, payload) {
			t.Fatalf("first frame lost or corrupted: got %d bytes, want %d", len(r.frame), len(payload))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the first frame never arrived: it was discarded with the read buffer")
	}
}

// captureConn buffers writes instead of sending them, so a test can control
// exactly how the bytes are segmented on the wire.
type captureConn struct {
	net.Conn
	Writer *bytes.Buffer
}

func (c *captureConn) Write(p []byte) (int, error) { return c.Writer.Write(p) }
