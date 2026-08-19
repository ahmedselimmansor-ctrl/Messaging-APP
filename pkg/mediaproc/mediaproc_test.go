package mediaproc

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestThumbnailPreservesAspectRatio(t *testing.T) {
	// A 800×400 source: every thumbnail must stay 2:1.
	src := encodePNG(t, 800, 400)

	for _, spec := range DefaultThumbnails {
		data, info, err := Thumbnail(src, spec)
		if err != nil {
			t.Fatalf("%s: %v", spec.Name, err)
		}
		if len(data) == 0 {
			t.Fatalf("%s: produced no bytes", spec.Name)
		}

		want := spec.MaxDim
		if want > 800 {
			want = 800 // never upscaled
		}
		if info.Width != want {
			t.Fatalf("%s: width = %d, want %d", spec.Name, info.Width, want)
		}
		if info.Height != want/2 {
			t.Fatalf("%s: height = %d, want %d (2:1 not preserved)", spec.Name, info.Height, want/2)
		}

		// The output must actually be a decodable JPEG, whatever went in.
		if _, err := jpeg.Decode(bytes.NewReader(data)); err != nil {
			t.Fatalf("%s: output is not valid JPEG: %v", spec.Name, err)
		}
	}
}

func TestThumbnailNeverUpscales(t *testing.T) {
	// A 40×40 source against a 1280px target: upscaling would add bytes and
	// no information.
	src := encodePNG(t, 40, 40)

	data, info, err := Thumbnail(src, ThumbnailSpec{Name: "_l", MaxDim: 1280, Quality: 85})
	if err != nil {
		t.Fatalf("thumbnail: %v", err)
	}
	if info.Width != 40 || info.Height != 40 {
		t.Fatalf("upscaled to %dx%d; the source was 40x40", info.Width, info.Height)
	}
	if len(data) == 0 {
		t.Fatal("produced no bytes")
	}
}

func TestThumbnailAcceptsEverySupportedFormat(t *testing.T) {
	spec := ThumbnailSpec{Name: "_m", MaxDim: 100, Quality: 80}

	t.Run("png", func(t *testing.T) {
		if _, _, err := Thumbnail(encodePNG(t, 200, 200), spec); err != nil {
			t.Fatalf("png: %v", err)
		}
	})
	t.Run("jpeg", func(t *testing.T) {
		if _, _, err := Thumbnail(encodeJPEG(t, 200, 200), spec); err != nil {
			t.Fatalf("jpeg: %v", err)
		}
	})
}

// TestProbeRejectsDecompressionBomb is the important one.
//
// A small PNG can declare enormous dimensions; decoding it would allocate
// gigabytes. DecodeConfig reads only the header, so the refusal happens
// before any pixels exist.
func TestProbeRejectsDecompressionBomb(t *testing.T) {
	// A hand-built PNG header claiming 50000×50000 — 2.5 billion pixels,
	// which at 4 bytes each is 10GB of RGBA.
	bomb := pngHeaderClaiming(50000, 50000)

	_, err := Probe(bytes.NewReader(bomb))
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("a 50000x50000 declaration was accepted: %v", err)
	}

	// The control. The identical construction at a sane size must be
	// accepted, which proves the rejection above came from the size guard and
	// not from the header being malformed — an easy way for this test to pass
	// for entirely the wrong reason.
	info, err := Probe(bytes.NewReader(pngHeaderClaiming(1000, 1000)))
	if err != nil {
		t.Fatalf("control: a well-formed 1000x1000 header was rejected: %v", err)
	}
	if info.Width != 1000 || info.Height != 1000 {
		t.Fatalf("control: got %dx%d, want 1000x1000", info.Width, info.Height)
	}
}

func TestProbeRejectsNonImage(t *testing.T) {
	_, err := Probe(strings.NewReader("this is not an image"))
	if !errors.Is(err, ErrUnsupportedImage) {
		t.Fatalf("got %v, want ErrUnsupportedImage", err)
	}
}

func TestFit(t *testing.T) {
	cases := []struct {
		w, h, max    int
		wantW, wantH int
	}{
		{800, 400, 400, 400, 200}, // landscape
		{400, 800, 400, 200, 400}, // portrait
		{100, 100, 400, 100, 100}, // already smaller
		{1000, 1, 100, 100, 1},    // extreme ratio must not round to zero
		{1, 1000, 100, 1, 100},
	}
	for _, c := range cases {
		gotW, gotH := fit(c.w, c.h, c.max)
		if gotW != c.wantW || gotH != c.wantH {
			t.Fatalf("fit(%d,%d,%d) = %d,%d want %d,%d",
				c.w, c.h, c.max, gotW, gotH, c.wantW, c.wantH)
		}
	}
}

// ---------------------------------------------------------------------------
// Virus scanning
// ---------------------------------------------------------------------------

// TestClamAVProtocol drives the real INSTREAM implementation against a stub
// clamd, which is what makes the wire format verifiable without installing
// ClamAV.
func TestClamAVProtocol(t *testing.T) {
	for _, tc := range []struct {
		name       string
		reply      string
		wantClean  bool
		wantThreat string
		wantErr    bool
	}{
		{"clean", "stream: OK\x00", true, "", false},
		{"infected", "stream: Eicar-Test-Signature FOUND\x00", false, "Eicar-Test-Signature", false},
		{"size limit", "INSTREAM size limit exceeded. ERROR\x00", false, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, received := stubClamd(t, tc.reply)

			c := NewClamAV(addr)
			payload := []byte("the file being scanned")

			result, err := c.Scan(context.Background(), bytes.NewReader(payload), int64(len(payload)))
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				if !errors.Is(err, ErrScanUnavailable) {
					t.Fatalf("got %v, want ErrScanUnavailable", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			if result.Clean != tc.wantClean {
				t.Fatalf("clean = %v, want %v", result.Clean, tc.wantClean)
			}
			if result.Threat != tc.wantThreat {
				t.Fatalf("threat = %q, want %q", result.Threat, tc.wantThreat)
			}

			// The stub reassembled the INSTREAM chunks; they must equal what
			// we handed in, or clamd would be scanning the wrong bytes.
			got := <-received
			if !bytes.Equal(got, payload) {
				t.Fatalf("clamd received %q, want %q", got, payload)
			}
		})
	}
}

func TestClamAVRefusesOversizeObject(t *testing.T) {
	c := NewClamAV("127.0.0.1:1") // never dialled
	c.MaxBytes = 1024

	_, err := c.Scan(context.Background(), bytes.NewReader(nil), 2048)
	if err == nil {
		t.Fatal("an object over the scan limit was accepted")
	}
	// It must be refused, not silently passed: a file too large to scan is a
	// file that must not be served, or the limit becomes the bypass.
	if errors.Is(err, ErrScanUnavailable) {
		t.Fatalf("reported as unavailable rather than refused: %v", err)
	}
}

func TestClamAVUnreachableIsNotClean(t *testing.T) {
	c := NewClamAV("127.0.0.1:1")
	c.Timeout = 2 * time.Second

	result, err := c.Scan(context.Background(), bytes.NewReader([]byte("x")), 1)
	if err == nil {
		t.Fatal("an unreachable scanner returned no error")
	}
	if result.Clean {
		t.Fatal("an unreachable scanner reported the file as clean")
	}
	if !errors.Is(err, ErrScanUnavailable) {
		t.Fatalf("got %v, want ErrScanUnavailable", err)
	}
}

func TestNoopScannerPassesEverything(t *testing.T) {
	r, err := NoopScanner{}.Scan(context.Background(), bytes.NewReader([]byte("anything")), 8)
	if err != nil || !r.Clean {
		t.Fatalf("noop scanner: %+v %v", r, err)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func encodePNG(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, color.RGBA{R: uint8(x % 256), G: uint8(y % 256), B: 128, A: 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("encode png: %v", err)
	}
	return buf.Bytes()
}

func encodeJPEG(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, color.RGBA{R: 200, G: uint8(y % 256), B: 50, A: 255})
		}
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 90}); err != nil {
		t.Fatalf("encode jpeg: %v", err)
	}
	return buf.Bytes()
}

// pngHeaderClaiming builds a PNG whose IHDR declares the given dimensions and
// carries no image data at all.
//
// The CRC must be correct. Go's png.DecodeConfig validates the IHDR checksum
// before it reports the dimensions, so a header with a wrong CRC is rejected
// as malformed and never reaches the size guard — which would make this test
// pass for entirely the wrong reason.
//
// A file of this shape is the decompression bomb in its purest form: 33 bytes
// on disk claiming 2.5 billion pixels.
func pngHeaderClaiming(w, h uint32) []byte {
	var buf bytes.Buffer
	buf.Write([]byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'})

	ihdr := make([]byte, 13)
	binary.BigEndian.PutUint32(ihdr[0:4], w)
	binary.BigEndian.PutUint32(ihdr[4:8], h)
	ihdr[8] = 8  // bit depth
	ihdr[9] = 6  // colour type: RGBA
	ihdr[10] = 0 // compression
	ihdr[11] = 0 // filter
	ihdr[12] = 0 // interlace

	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(ihdr)))
	buf.Write(length[:])
	buf.WriteString("IHDR")
	buf.Write(ihdr)

	// The chunk CRC covers the type and the data, not the length.
	crc := crc32.NewIEEE()
	_, _ = crc.Write([]byte("IHDR"))
	_, _ = crc.Write(ihdr)
	var sum [4]byte
	binary.BigEndian.PutUint32(sum[:], crc.Sum32())
	buf.Write(sum[:])

	return buf.Bytes()
}

// stubClamd speaks enough of the INSTREAM protocol to verify the client.
func stubClamd(t *testing.T, reply string) (addr string, received chan []byte) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	received = make(chan []byte, 1)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

		// Read the zINSTREAM\0 command.
		cmd := make([]byte, 10)
		if _, err := io.ReadFull(conn, cmd); err != nil {
			return
		}
		if string(cmd) != "zINSTREAM\x00" {
			t.Errorf("clamd got command %q, want zINSTREAM", cmd)
			return
		}

		// Reassemble the length-prefixed chunks until the zero terminator.
		var body bytes.Buffer
		for {
			var header [4]byte
			if _, err := io.ReadFull(conn, header[:]); err != nil {
				return
			}
			n := binary.BigEndian.Uint32(header[:])
			if n == 0 {
				break
			}
			chunk := make([]byte, n)
			if _, err := io.ReadFull(conn, chunk); err != nil {
				return
			}
			body.Write(chunk)
		}

		received <- body.Bytes()
		_, _ = conn.Write([]byte(reply))
	}()

	return ln.Addr().String(), received
}
