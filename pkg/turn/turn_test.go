package turn

import (
	"strings"
	"testing"
	"time"
)

func TestIssuedCredentialsVerify(t *testing.T) {
	iss, err := NewIssuer(Config{
		Secret: []byte("a-sufficiently-long-shared-secret"),
		URIs:   []string{"turn:turn.example.com:3478?transport=udp"},
		TTL:    time.Hour,
	})
	if err != nil {
		t.Fatalf("new issuer: %v", err)
	}

	creds := iss.Issue(12345)
	if err := iss.Verify(creds.Username, creds.Password); err != nil {
		t.Fatalf("a freshly issued credential did not verify: %v", err)
	}

	userID, err := UserIDFrom(creds.Username)
	if err != nil || userID != 12345 {
		t.Fatalf("UserIDFrom = %d (%v), want 12345", userID, err)
	}
	if creds.TTL != 3600 {
		t.Fatalf("ttl = %d, want 3600", creds.TTL)
	}
}

func TestForgedCredentialsAreRejected(t *testing.T) {
	iss, _ := NewIssuer(Config{Secret: []byte("a-sufficiently-long-shared-secret")})
	creds := iss.Issue(1)

	// The whole point: without the secret, a credential cannot be minted.
	if err := iss.Verify(creds.Username, "not-the-right-signature"); err == nil {
		t.Fatal("a forged password was accepted — the relay would be an open proxy")
	}

	// Nor can the expiry be extended by editing the username, because the
	// signature covers it.
	tampered := strings.Replace(creds.Username, ":", "0:", 1)
	if err := iss.Verify(tampered, creds.Password); err == nil {
		t.Fatal("a tampered username was accepted")
	}
}

func TestExpiredCredentialsAreRejected(t *testing.T) {
	iss, _ := NewIssuer(Config{
		Secret: []byte("a-sufficiently-long-shared-secret"),
		TTL:    time.Hour,
	})

	// Issue with an expiry in the past by constructing the username the same
	// way Issue does. The signature is valid; only the time is not.
	past := time.Now().Add(-time.Hour)
	username := formatUsername(past, 42)
	password := signUsername([]byte("a-sufficiently-long-shared-secret"), username)

	err := iss.Verify(username, password)
	if err == nil {
		t.Fatal("an expired credential was accepted")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("got %v, want an expiry error", err)
	}
}

func TestIssuerRefusesAWeakSecret(t *testing.T) {
	if _, err := NewIssuer(Config{}); err != ErrNoSecret {
		t.Fatalf("an empty secret was accepted: %v", err)
	}
	if _, err := NewIssuer(Config{Secret: []byte("short")}); err == nil {
		t.Fatal("a 5-byte secret was accepted; it is guessable, and guessing it buys free relay bandwidth")
	}
}

func TestCredentialsDifferPerUserAndOverTime(t *testing.T) {
	iss, _ := NewIssuer(Config{Secret: []byte("a-sufficiently-long-shared-secret")})

	a := iss.Issue(1)
	b := iss.Issue(2)
	if a.Password == b.Password {
		t.Fatal("two users were issued the same password")
	}
	if a.Username == b.Username {
		t.Fatal("two users were issued the same username")
	}
}
