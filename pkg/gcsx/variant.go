package gcsx

import (
	"path"
	"strings"
)

// knownVariantSuffixes are the derivative names the media processor produces.
//
// They are listed explicitly rather than pattern-matched. A rule like
// "anything after the last underscore" would let a crafted path resolve to a
// *different* object's key, which is a permission-confusion bug in the one
// function whose whole job is deciding permissions. An allowlist cannot do
// that.
var knownVariantSuffixes = []string{
	"_s", "_m", "_l", "_poster", "_720p", "_480p",
}

// ACLKey maps any object path — an original or one of its derivatives — onto
// the single key their permissions are recorded under.
//
// Derivatives deliberately have no ACL row of their own. A thumbnail must
// inherit its original's permissions automatically, and giving each variant
// its own row would mean five places to get a revocation right instead of one.
//
// The extension is dropped as well as the variant suffix, because the original
// may be a .jpg while its thumbnail is a .jpg and its poster frame came from a
// .mp4. The stem is what they share.
//
//	photo/2026/08/17/42/abc-uuid.jpg    -> photo/2026/08/17/42/abc-uuid
//	photo/2026/08/17/42/abc-uuid_s.jpg  -> photo/2026/08/17/42/abc-uuid
//	video/2026/08/17/42/xyz_poster.jpg  -> video/2026/08/17/42/xyz
//	video/2026/08/17/42/xyz_720p.mp4    -> video/2026/08/17/42/xyz
func ACLKey(object string) string {
	dir := path.Dir(object)
	base := strings.TrimSuffix(path.Base(object), path.Ext(object))

	for _, suffix := range knownVariantSuffixes {
		if stem := strings.TrimSuffix(base, suffix); stem != base && stem != "" {
			base = stem
			break
		}
	}

	if dir == "." {
		return base
	}
	return path.Join(dir, base)
}

// IsVariant reports whether an object path is a derivative rather than an
// original.
func IsVariant(object string) bool {
	base := strings.TrimSuffix(path.Base(object), path.Ext(object))
	for _, suffix := range knownVariantSuffixes {
		if stem := strings.TrimSuffix(base, suffix); stem != base && stem != "" {
			return true
		}
	}
	return false
}
