package gcsx

import "testing"

// ACLKey decides permissions, so its edge cases are security-relevant: two
// different objects that collapse to the same key would share access.

func TestACLKeyMapsVariantsOntoTheirOriginal(t *testing.T) {
	const original = "photo/2026/08/17/42/abc-uuid.jpg"
	want := "photo/2026/08/17/42/abc-uuid"

	cases := []string{
		original,
		"photo/2026/08/17/42/abc-uuid_s.jpg",
		"photo/2026/08/17/42/abc-uuid_m.jpg",
		"photo/2026/08/17/42/abc-uuid_l.jpg",
	}
	for _, object := range cases {
		if got := ACLKey(object); got != want {
			t.Fatalf("ACLKey(%q) = %q, want %q", object, got, want)
		}
	}
}

func TestACLKeyHandlesVideoDerivatives(t *testing.T) {
	want := "video/2026/08/17/42/xyz"
	for _, object := range []string{
		"video/2026/08/17/42/xyz.mp4",
		"video/2026/08/17/42/xyz_poster.jpg", // a JPEG derived from an MP4
		"video/2026/08/17/42/xyz_720p.mp4",
	} {
		if got := ACLKey(object); got != want {
			t.Fatalf("ACLKey(%q) = %q, want %q", object, got, want)
		}
	}
}

// TestACLKeyDoesNotCollapseDistinctObjects is the one that matters.
//
// If two genuinely different uploads mapped onto the same key, membership in
// one chat would grant access to the other's media.
func TestACLKeyDoesNotCollapseDistinctObjects(t *testing.T) {
	distinct := []string{
		"photo/2026/08/17/42/aaa.jpg",
		"photo/2026/08/17/42/bbb.jpg",
		"photo/2026/08/17/99/aaa.jpg", // same name, different uploader directory
		"video/2026/08/17/42/aaa.mp4", // same name, different kind prefix
		"photo/2026/08/18/42/aaa.jpg", // same name, different day
	}

	seen := make(map[string]string, len(distinct))
	for _, object := range distinct {
		key := ACLKey(object)
		if prev, clash := seen[key]; clash {
			t.Fatalf("%q and %q both map to %q; membership in one chat would grant the other's media",
				prev, object, key)
		}
		seen[key] = object
	}
}

// TestACLKeyIgnoresUnknownSuffixes guards the allowlist.
//
// A rule like "strip anything after the last underscore" would let a caller
// ask for "…/victim_anything.jpg" and be granted the permissions of
// "…/victim". Only the suffixes the media processor actually produces may be
// stripped.
func TestACLKeyIgnoresUnknownSuffixes(t *testing.T) {
	cases := map[string]string{
		"photo/2026/08/17/42/abc_evil.jpg":  "photo/2026/08/17/42/abc_evil",
		"photo/2026/08/17/42/abc_xl.jpg":    "photo/2026/08/17/42/abc_xl",
		"photo/2026/08/17/42/abc_1080p.mp4": "photo/2026/08/17/42/abc_1080p",
		"photo/2026/08/17/42/abc_.jpg":      "photo/2026/08/17/42/abc_",
	}
	for object, want := range cases {
		if got := ACLKey(object); got != want {
			t.Fatalf("ACLKey(%q) = %q, want %q — an unknown suffix was stripped", object, got, want)
		}
	}
}

func TestACLKeyRefusesToProduceAnEmptyStem(t *testing.T) {
	// An object literally named "_s.jpg" must not collapse to the directory,
	// which would be a key shared by every such file in it.
	got := ACLKey("photo/2026/08/17/42/_s.jpg")
	if got == "photo/2026/08/17/42" {
		t.Fatalf("ACLKey collapsed to the directory %q", got)
	}
	if got != "photo/2026/08/17/42/_s" {
		t.Fatalf("ACLKey = %q, want photo/2026/08/17/42/_s", got)
	}
}

func TestIsVariant(t *testing.T) {
	variants := []string{
		"photo/a/b/uuid_s.jpg",
		"photo/a/b/uuid_m.jpg",
		"video/a/b/uuid_poster.jpg",
		"video/a/b/uuid_720p.mp4",
	}
	for _, v := range variants {
		if !IsVariant(v) {
			t.Fatalf("IsVariant(%q) = false", v)
		}
	}

	originals := []string{
		"photo/a/b/uuid.jpg",
		"video/a/b/uuid.mp4",
		"file/a/b/uuid.pdf",
		"photo/a/b/uuid_evil.jpg",
	}
	for _, o := range originals {
		if IsVariant(o) {
			t.Fatalf("IsVariant(%q) = true", o)
		}
	}
}

func TestSanitiseFilename(t *testing.T) {
	// The filename lands in a Content-Disposition header, so anything that
	// could break out of the quoted string is a header-injection vector.
	cases := map[string]string{
		`photo.jpg`:          "photo.jpg",
		`../../etc/passwd`:   "passwd",
		`a"b.jpg`:            "a_b.jpg",
		`a\b.jpg`:            "a_b.jpg",
		"a\r\nX-Evil: 1.jpg": "a__X-Evil: 1.jpg",
		``:                   "file",
		`/`:                  "file",
		`.`:                  "file",
		`..`:                 "file",
		`../..`:              "file",
	}
	for in, want := range cases {
		if got := sanitiseFilename(in); got != want {
			t.Fatalf("sanitiseFilename(%q) = %q, want %q", in, got, want)
		}
	}
}
