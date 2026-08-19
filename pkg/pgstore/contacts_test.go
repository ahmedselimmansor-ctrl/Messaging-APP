package pgstore

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

// PhoneHash must agree exactly with what the SQL in Contacts.Import computes,
// or contact discovery silently matches nothing — a failure that looks like
// "none of my contacts use the app" rather than like a bug.
//
// The SQL is:
//
//	translate(encode(hmac(phone, pepper, 'sha256'), 'base64'), '+/=', '-_')
//
// which is standard base64 with '+' -> '-', '/' -> '_' and '=' removed.
// That is exactly base64.RawURLEncoding.
func TestPhoneHashMatchesTheSQLEncoding(t *testing.T) {
	pepper := []byte("test-pepper-value")
	phone := "+201234567890"

	got := PhoneHash(pepper, phone)

	// Recompute the way Postgres would: standard base64, then translate.
	mac := hmac.New(sha256.New, pepper)
	mac.Write([]byte(phone))
	std := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	var want []byte
	for i := 0; i < len(std); i++ {
		switch std[i] {
		case '+':
			want = append(want, '-')
		case '/':
			want = append(want, '_')
		case '=':
			// translate() with a shorter "to" string deletes the character.
		default:
			want = append(want, std[i])
		}
	}

	if got != string(want) {
		t.Fatalf("PhoneHash = %q, but the SQL would produce %q", got, string(want))
	}
}

func TestPhoneHashIsStableAndPepperDependent(t *testing.T) {
	a := PhoneHash([]byte("pepper-one"), "+201234567890")
	again := PhoneHash([]byte("pepper-one"), "+201234567890")
	if a != again {
		t.Fatal("PhoneHash is not deterministic")
	}

	b := PhoneHash([]byte("pepper-two"), "+201234567890")
	if a == b {
		t.Fatal("changing the pepper did not change the hash")
	}

	c := PhoneHash([]byte("pepper-one"), "+201234567891")
	if a == c {
		t.Fatal("different numbers produced the same hash")
	}
}

func TestPhoneHashIsURLSafe(t *testing.T) {
	// The hash travels in a JSON body and sometimes a query string, so it
	// must not contain characters that need escaping.
	for _, phone := range []string{
		"+201234567890", "+12025550123", "+447700900123", "+8613800138000",
	} {
		h := PhoneHash([]byte("pepper"), phone)
		for _, r := range h {
			ok := (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') ||
				(r >= '0' && r <= '9') || r == '-' || r == '_'
			if !ok {
				t.Fatalf("PhoneHash(%s) contains %q, which is not URL-safe", phone, r)
			}
		}
	}
}
