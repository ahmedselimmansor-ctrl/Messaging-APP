// Package turn issues time-limited TURN credentials.
//
// A TURN server relays media for peers behind NATs that refuse a direct path.
// That relay costs real bandwidth, which makes an open TURN server a free
// proxy for anyone who finds it — and they will.
//
// The defence is the REST API mechanism described in
// draft-uberti-behave-turn-rest: the username is an expiry timestamp and the
// password is HMAC-SHA1 over it, keyed by a secret shared with the TURN
// server. Nobody without the secret can mint a credential, and every
// credential stops working on its own. There is no credential database and
// nothing to revoke.
package turn

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Config describes the TURN deployment.
type Config struct {
	// Secret is shared with the TURN server (coturn's static-auth-secret).
	// It is the only thing standing between the relay and the open internet.
	Secret []byte
	// URIs are the TURN endpoints, e.g. turn:turn.example.com:3478?transport=udp
	URIs []string
	// STUNURIs need no credentials: a STUN server only reports the address it
	// observes, which is not worth protecting.
	STUNURIs []string
	// TTL is how long a credential lives.
	TTL time.Duration
}

// DefaultConfig returns sane values.
func DefaultConfig() Config {
	return Config{
		// Long enough for a call to start and to survive a network change
		// mid-call; short enough that a leaked credential is worthless
		// tomorrow.
		TTL: 12 * time.Hour,
	}
}

// Credentials are what a client hands to its WebRTC stack.
type Credentials struct {
	Username string   `json:"username"`
	Password string   `json:"password"`
	URIs     []string `json:"uris"`
	STUNURIs []string `json:"stun_uris,omitempty"`
	TTL      int      `json:"ttl"`
	// ExpiresAt is informational, so a client can refresh before a long call
	// outlives its credential.
	ExpiresAt time.Time `json:"expires_at"`
}

// ErrNoSecret means the deployment has no TURN secret configured.
var ErrNoSecret = errors.New("turn: no shared secret configured")

// Issuer mints credentials.
type Issuer struct{ cfg Config }

// NewIssuer builds an issuer.
func NewIssuer(cfg Config) (*Issuer, error) {
	if len(cfg.Secret) == 0 {
		return nil, ErrNoSecret
	}
	if len(cfg.Secret) < 16 {
		// A short secret is guessable, and guessing it grants unlimited relay
		// bandwidth on someone else's bill.
		return nil, fmt.Errorf("turn: the shared secret must be at least 16 bytes, got %d", len(cfg.Secret))
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 12 * time.Hour
	}
	return &Issuer{cfg: cfg}, nil
}

// Issue mints credentials for one user.
//
// The username is "<unix-expiry>:<user-id>". Binding the user id into it means
// the TURN server's logs attribute relayed bandwidth to an account, which is
// what makes abuse traceable rather than merely rate-limited.
func (i *Issuer) Issue(userID int64) Credentials {
	expiry := time.Now().Add(i.cfg.TTL)
	username := formatUsername(expiry, userID)
	password := signUsername(i.cfg.Secret, username)

	return Credentials{
		Username:  username,
		Password:  password,
		URIs:      i.cfg.URIs,
		STUNURIs:  i.cfg.STUNURIs,
		TTL:       int(i.cfg.TTL.Seconds()),
		ExpiresAt: expiry,
	}
}

// Verify checks a credential the way the TURN server does.
//
// Used only in tests and in the operational check that confirms this service
// and coturn agree on the secret — a mismatch there means every call silently
// fails to relay, with no error anywhere except the client's ICE state.
func (i *Issuer) Verify(username, password string) error {
	parts := strings.SplitN(username, ":", 2)
	if len(parts) != 2 {
		return errors.New("turn: malformed username")
	}

	expiry, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return fmt.Errorf("turn: malformed expiry: %w", err)
	}
	if time.Now().Unix() > expiry {
		return errors.New("turn: credential has expired")
	}

	want := signUsername(i.cfg.Secret, username)

	// Constant time: a byte-by-byte compare would let an attacker recover a
	// valid password one character at a time.
	if !hmac.Equal([]byte(want), []byte(password)) {
		return errors.New("turn: credential signature does not match")
	}
	return nil
}

// UserIDFrom extracts the account a credential was issued to, for attributing
// relay bandwidth in the TURN server's logs.
func UserIDFrom(username string) (int64, error) {
	parts := strings.SplitN(username, ":", 2)
	if len(parts) != 2 {
		return 0, errors.New("turn: malformed username")
	}
	return strconv.ParseInt(parts[1], 10, 64)
}

// formatUsername and signUsername are the two halves of Issue, exposed so a
// test can build a credential with a chosen expiry — which is the only way to
// exercise the expiry path without waiting.
func formatUsername(expiry time.Time, userID int64) string {
	return fmt.Sprintf("%d:%d", expiry.Unix(), userID)
}

func signUsername(secret []byte, username string) string {
	mac := hmac.New(sha1.New, secret)
	mac.Write([]byte(username))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}
