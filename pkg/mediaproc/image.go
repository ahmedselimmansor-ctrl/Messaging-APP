// Package mediaproc turns an uploaded object into the derivatives a client
// needs: thumbnails, a probed duration, a transcoded video.
//
// It is deliberately split from the consumer that drives it so the
// transformations are testable without Kafka, GCS or ffmpeg.
package mediaproc

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/draw"
	"image/gif"
	"image/jpeg"
	"image/png"
	"io"

	"golang.org/x/image/webp"
)

// ThumbnailSpec describes one derivative to produce.
type ThumbnailSpec struct {
	// Name becomes a suffix on the object path, e.g. "_thumb".
	Name string
	// MaxDim bounds the longest edge. Aspect ratio is always preserved —
	// cropping to a square is a client decision, not ours, because a chat
	// list and a full-screen viewer want different crops of the same image.
	MaxDim int
	// Quality is the JPEG quality, 1..100.
	Quality int
}

// DefaultThumbnails are the sizes the clients ask for.
//
// Three, not one. A 96px avatar and a 1280px preview differ by two orders of
// magnitude in bytes, and serving the large one to a chat list would dominate
// the mobile data budget of the whole app.
var DefaultThumbnails = []ThumbnailSpec{
	{Name: "_s", MaxDim: 96, Quality: 70},   // chat list, avatars
	{Name: "_m", MaxDim: 320, Quality: 78},  // inline in a conversation
	{Name: "_l", MaxDim: 1280, Quality: 85}, // tapped, before the original loads
}

// ImageInfo is what a decode tells us about an image.
type ImageInfo struct {
	Width  int
	Height int
	Format string
}

// MaxDecodePixels bounds the image we are willing to decode.
//
// This is the decompression-bomb guard. A 20KB PNG can declare 50000×50000,
// which is 10GB of RGBA once decoded — the classic way to OOM an image
// pipeline with a file that looks harmless at rest. image.DecodeConfig reads
// only the header, so the dimensions are known before any pixels are
// allocated.
const MaxDecodePixels = 64_000_000 // ~64MP, comfortably above any real photo

// Errors.
var (
	ErrTooLarge         = errors.New("mediaproc: image dimensions exceed the decode limit")
	ErrUnsupportedImage = errors.New("mediaproc: unsupported image format")
)

// Probe reads only the header and returns the dimensions.
func Probe(r io.Reader) (ImageInfo, error) {
	cfg, format, err := image.DecodeConfig(r)
	if err != nil {
		return ImageInfo{}, fmt.Errorf("%w: %v", ErrUnsupportedImage, err)
	}
	if int64(cfg.Width)*int64(cfg.Height) > MaxDecodePixels {
		return ImageInfo{}, fmt.Errorf("%w: %dx%d", ErrTooLarge, cfg.Width, cfg.Height)
	}
	return ImageInfo{Width: cfg.Width, Height: cfg.Height, Format: format}, nil
}

// Thumbnail decodes src and produces a JPEG bounded by spec.MaxDim.
//
// Output is always JPEG regardless of input format. That is a deliberate
// narrowing: it means one decoder path on every client, no animated-GIF
// surprises in a chat list, and no chance of a crafted PNG chunk reaching a
// client's decoder through a path we control.
func Thumbnail(src []byte, spec ThumbnailSpec) ([]byte, ImageInfo, error) {
	info, err := Probe(bytes.NewReader(src))
	if err != nil {
		return nil, ImageInfo{}, err
	}

	img, err := decode(src, info.Format)
	if err != nil {
		return nil, info, err
	}

	bounds := img.Bounds()
	w, h := bounds.Dx(), bounds.Dy()
	tw, th := fit(w, h, spec.MaxDim)

	// An image already smaller than the target is re-encoded rather than
	// upscaled: upscaling adds bytes and no information.
	if tw >= w && th >= h {
		tw, th = w, h
	}

	dst := image.NewRGBA(image.Rect(0, 0, tw, th))

	// White background: a transparent PNG flattened onto black looks broken,
	// and JPEG has no alpha channel to preserve it with.
	draw.Draw(dst, dst.Bounds(), image.NewUniform(whiteOpaque), image.Point{}, draw.Src)
	scale(dst, img)

	var out bytes.Buffer
	q := spec.Quality
	if q <= 0 || q > 100 {
		q = 80
	}
	if err := jpeg.Encode(&out, dst, &jpeg.Options{Quality: q}); err != nil {
		return nil, info, fmt.Errorf("mediaproc: encode thumbnail: %w", err)
	}

	return out.Bytes(), ImageInfo{Width: tw, Height: th, Format: "jpeg"}, nil
}

func decode(src []byte, format string) (image.Image, error) {
	r := bytes.NewReader(src)
	switch format {
	case "jpeg":
		return jpeg.Decode(r)
	case "png":
		return png.Decode(r)
	case "gif":
		// Only the first frame. Animating a thumbnail is a client decision
		// and decoding every frame of a long GIF is an easy memory blowup.
		return gif.Decode(r)
	case "webp":
		return webp.Decode(r)
	}
	return nil, fmt.Errorf("%w: %s", ErrUnsupportedImage, format)
}

// fit returns the largest size within maxDim that preserves the aspect ratio.
func fit(w, h, maxDim int) (int, int) {
	if maxDim <= 0 || (w <= maxDim && h <= maxDim) {
		return w, h
	}
	if w >= h {
		nh := h * maxDim / w
		if nh < 1 {
			nh = 1
		}
		return maxDim, nh
	}
	nw := w * maxDim / h
	if nw < 1 {
		nw = 1
	}
	return nw, maxDim
}
