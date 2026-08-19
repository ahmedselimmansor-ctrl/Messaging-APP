package secretchat

import (
	"errors"
	"math/big"
	"strings"
	"testing"
)

// TestExchangeProducesTheSameKey is the whole point of the package: two
// parties who never share a secret arrive at the same 256-byte key, and the
// values that travel between them do not reveal it.
func TestExchangeProducesTheSameKey(t *testing.T) {
	for i := 0; i < 20; i++ {
		a, err := GenerateExponent()
		if err != nil {
			t.Fatalf("generate a: %v", err)
		}
		b, err := GenerateExponent()
		if err != nil {
			t.Fatalf("generate b: %v", err)
		}

		gA := PublicValue(a)
		gB := PublicValue(b)

		keyA, err := DeriveKey(gB, a)
		if err != nil {
			t.Fatalf("derive on A: %v", err)
		}
		keyB, err := DeriveKey(gA, b)
		if err != nil {
			t.Fatalf("derive on B: %v", err)
		}

		if string(keyA) != string(keyB) {
			t.Fatal("the two parties derived different keys")
		}
		if len(keyA) != KeySize {
			t.Fatalf("key is %d bytes, want %d", len(keyA), KeySize)
		}
		if Fingerprint(keyA) != Fingerprint(keyB) {
			t.Fatal("fingerprints differ for identical keys")
		}
	}
}

// TestPadKeyHandlesShortSecrets guards the bug that would appear in roughly
// one exchange in 256: big.Int.Bytes() drops leading zeros, so a shared secret
// with a zero top byte comes back short and the two sides would derive keys of
// different lengths from the same secret.
//
// The padding is tested directly rather than through DeriveKey because
// producing a short secret end to end means searching for a specific exponent
// pair — the small values that would make it easy to contrive are correctly
// refused by ValidateDHValue.
func TestPadKeyHandlesShortSecrets(t *testing.T) {
	for _, length := range []int{1, 100, 254, 255, KeySize} {
		raw := make([]byte, length)
		for i := range raw {
			raw[i] = byte(i + 1)
		}

		key := padKey(raw)
		if len(key) != KeySize {
			t.Fatalf("a %d byte secret produced a %d byte key, want %d", length, len(key), KeySize)
		}

		// The value must be right-aligned: the secret's bytes end up at the
		// end, with zeros in front. Left-aligning would change the key.
		for i := 0; i < KeySize-length; i++ {
			if key[i] != 0 {
				t.Fatalf("a %d byte secret was not left-padded; byte %d is %d", length, i, key[i])
			}
		}
		if string(key[KeySize-length:]) != string(raw) {
			t.Fatalf("a %d byte secret was not right-aligned in the key", length)
		}
	}
}

// TestDeriveKeyIsAlwaysFullLength does the end-to-end version.
//
// Real exponents are used, so this covers the path a genuine exchange takes.
func TestDeriveKeyIsAlwaysFullLength(t *testing.T) {
	for i := 0; i < 30; i++ {
		a, _ := GenerateExponent()
		b, _ := GenerateExponent()

		key, err := DeriveKey(PublicValue(b), a)
		if err != nil {
			t.Fatalf("derive: %v", err)
		}
		if len(key) != KeySize {
			t.Fatalf("key is %d bytes, want %d", len(key), KeySize)
		}
	}
}

func TestValidateDHValueRejectsDegenerateValues(t *testing.T) {
	one := big.NewInt(1)
	p := Prime()

	cases := map[string]*big.Int{
		"zero":            big.NewInt(0),
		"one":             one,
		"two":             big.NewInt(2),
		"p":               new(big.Int).Set(p),
		"p minus one":     new(big.Int).Sub(p, one),
		"just above zero": big.NewInt(1 << 20),
	}
	for name, v := range cases {
		if err := ValidateDHValue(v); !errors.Is(err, ErrBadDHValue) {
			t.Fatalf("%s: got %v, want ErrBadDHValue", name, err)
		}
	}

	// A legitimate public value must pass.
	x, _ := GenerateExponent()
	if err := ValidateDHValue(PublicValue(x)); err != nil {
		t.Fatalf("a genuine public value was rejected: %v", err)
	}
}

func TestDeriveKeyRejectsADegeneratePeerValue(t *testing.T) {
	own, _ := GenerateExponent()

	// A peer sending g_b = 1 would force the shared secret to 1 and read
	// everything afterwards. This is the check that stops it.
	if _, err := DeriveKey(big.NewInt(1), own); !errors.Is(err, ErrBadDHValue) {
		t.Fatalf("got %v, want ErrBadDHValue", err)
	}
}

func TestVerifyFingerprint(t *testing.T) {
	a, _ := GenerateExponent()
	b, _ := GenerateExponent()
	key, _ := DeriveKey(PublicValue(b), a)

	if err := VerifyFingerprint(key, Fingerprint(key)); err != nil {
		t.Fatalf("a matching fingerprint was rejected: %v", err)
	}
	if err := VerifyFingerprint(key, Fingerprint(key)+1); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("got %v, want ErrKeyMismatch", err)
	}
}

// TestVisualFingerprintIsStableAndSensitive covers the property users depend
// on when they read the sequence aloud to each other.
func TestVisualFingerprintIsStableAndSensitive(t *testing.T) {
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	first := VisualFingerprint(key)
	if len(first) != 5 {
		t.Fatalf("got %d words, want 5", len(first))
	}
	for _, w := range first {
		if len(w) < 3 {
			t.Fatalf("word %q is too short to hear reliably over a phone call", w)
		}
		if strings.TrimSpace(w) != w {
			t.Fatalf("word %q has surrounding whitespace", w)
		}
	}

	again := VisualFingerprint(key)
	if strings.Join(first, " ") != strings.Join(again, " ") {
		t.Fatal("the visual fingerprint is not deterministic")
	}

	// A single flipped bit must change the sequence, or a substituted key
	// could pass a visual comparison.
	other := make([]byte, KeySize)
	copy(other, key)
	other[0] ^= 0x01

	if strings.Join(VisualFingerprint(other), " ") == strings.Join(first, " ") {
		t.Fatal("flipping one bit of the key produced the same visual fingerprint")
	}
}

// TestVisualFingerprintDistribution checks the bit-packing actually spreads
// across the word list. A packing bug that always selected from the first few
// entries would collapse the effective entropy without failing any other test.
func TestVisualFingerprintDistribution(t *testing.T) {
	seen := make(map[string]int)

	for i := 0; i < 2000; i++ {
		key := make([]byte, KeySize)
		key[0] = byte(i)
		key[1] = byte(i >> 8)
		for _, w := range VisualFingerprint(key) {
			seen[w]++
		}
	}

	// 2000 samples × 5 words drawn from 2048 entries should touch a large
	// fraction of the list. Fewer than 500 distinct words would mean the
	// packing is masking bits.
	if len(seen) < 500 {
		t.Fatalf("only %d distinct words across 10000 draws; the bit packing is losing entropy", len(seen))
	}
}

func TestWordListIsExactlyElevenBits(t *testing.T) {
	if len(wordList) != 2048 {
		t.Fatalf("the word list has %d entries, want exactly 2048 (11 bits per word)", len(wordList))
	}

	seen := make(map[string]bool, len(wordList))
	for _, w := range wordList {
		if seen[w] {
			t.Fatalf("the word list contains a duplicate: %q", w)
		}
		seen[w] = true
	}
}
