package push

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTruncateNeverSplitsACharacter(t *testing.T) {
	// The byte limits here come from APNs and FCM; the content is arbitrary
	// user text. A naive s[:n] cuts a multi-byte rune in half and produces
	// invalid UTF-8, which the push provider then rejects — or worse, renders
	// as a replacement character on someone's lock screen.
	cases := []struct {
		name string
		in   string
		n    int
	}{
		{"ascii under the limit", "hello", 64},
		{"ascii over the limit", strings.Repeat("a", 100), 64},
		{"arabic", strings.Repeat("مرحبا", 40), 64},
		{"emoji", strings.Repeat("👋🏽", 40), 64},
		{"mixed", "chat-" + strings.Repeat("日本語", 30), 64},
		{"cut exactly on a boundary", "aé", 2},
		{"cut inside a two-byte rune", "aé", 2},
		{"cut inside a four-byte rune", "a👋", 3},
		{"limit of zero", "anything", 0},
		{"limit of one inside a rune", "é", 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := truncate(tc.in, tc.n)

			if len(got) > tc.n {
				t.Errorf("truncate returned %d bytes, over the limit of %d", len(got), tc.n)
			}
			if !utf8.ValidString(got) {
				t.Errorf("truncate produced invalid UTF-8: %q", got)
			}
			if !strings.HasPrefix(tc.in, got) {
				t.Errorf("truncate returned %q which is not a prefix of the input", got)
			}
		})
	}
}

func TestTruncateKeepsShortStringsIntact(t *testing.T) {
	// The common case: nothing is over the limit, so nothing should change.
	for _, s := range []string{"", "a", "مرحبا", "👋🏽", strings.Repeat("x", 64)} {
		if got := truncate(s, 64); got != s {
			t.Errorf("truncate(%q, 64) = %q, want it unchanged", s, got)
		}
	}
}

func TestTruncateLosesAtMostThreeBytes(t *testing.T) {
	// Walking back to a rune boundary must not walk far. UTF-8 is at most four
	// bytes wide, so the loss is bounded at three — a bug that walked back
	// further would silently shorten every notification.
	long := strings.Repeat("👋", 100) // four bytes each
	for n := 4; n < 40; n++ {
		got := truncate(long, n)
		if lost := n - len(got); lost > 3 {
			t.Errorf("truncate(_, %d) dropped %d bytes, want at most 3", n, lost)
		}
	}
}
