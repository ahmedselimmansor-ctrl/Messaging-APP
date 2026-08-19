package mediaproc

import (
	"image"
	"image/color"

	"golang.org/x/image/draw"
)

// whiteOpaque is the background a transparent source is flattened onto.
var whiteOpaque = color.RGBA{R: 0xff, G: 0xff, B: 0xff, A: 0xff}

// scale resamples src into dst.
//
// CatmullRom rather than the cheaper ApproxBiLinear: thumbnails are generated
// once and viewed many times, so the extra CPU is amortised to nothing while
// the quality difference at small sizes — where downscaling artefacts are most
// visible — is obvious.
func scale(dst *image.RGBA, src image.Image) {
	draw.CatmullRom.Scale(dst, dst.Bounds(), src, src.Bounds(), draw.Over, nil)
}
