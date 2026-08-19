// Package authn issues and verifies the credentials the platform accepts.
//
// There are two credential families and they exist for different clients:
//
//   - JWT access/refresh tokens for the REST and GraphQL surface, verified
//     statelessly at every service so a token check never becomes a network
//     call.
//   - MTProto auth keys for the realtime gateway, which are long-lived shared
//     secrets negotiated by the DH handshake and resolved to a session via
//     Redis (with Postgres as the durable fallback).
//
// Signing keys are RSA or ECDSA private keys held in Secret Manager and
// mounted as environment variables. Rotation is handled by publishing a new
// key id: verifiers accept every key in the JWKS, issuers sign with the
// newest, so a rotation never invalidates live sessions.
package authn

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pervagans/messaging-app/pkg/httpx"
)

// Errors returned by verification.
var (
	ErrNoToken      = errors.New("authn: no credential presented")
	ErrInvalidToken = errors.New("authn: credential is invalid")
	ErrExpired      = errors.New("authn: credential has expired")
	ErrWrongType    = errors.New("authn: wrong token type")
)

// TokenType distinguishes the two JWTs we issue.
type TokenType string

const (
	// AccessToken is short-lived and carries the user and device identity.
	AccessToken TokenType = "access"
	// RefreshToken is long-lived, single-purpose and only the auth service
	// accepts it. Keeping refresh out of the access path means a leaked
	// access token expires on its own within minutes.
	RefreshToken TokenType = "refresh"
)

// Claims is the JWT payload.
type Claims struct {
	jwt.RegisteredClaims
	Type     TokenType `json:"typ"`
	UserID   int64     `json:"uid"`
	DeviceID int64     `json:"did"`
	// Scopes allow a device to hold a reduced-privilege token, e.g. a web
	// session that may read but not change account settings.
	Scopes []string `json:"scp,omitempty"`
}

// HasScope reports whether the token carries a scope. An empty scope list
// means full privileges, which is what a normal mobile session gets.
func (c *Claims) HasScope(s string) bool {
	if len(c.Scopes) == 0 {
		return true
	}
	for _, have := range c.Scopes {
		if have == s {
			return true
		}
	}
	return false
}

// Issuer signs tokens.
type Issuer struct {
	key   *ecdsa.PrivateKey
	keyID string

	issuer   string
	audience string

	accessTTL  time.Duration
	refreshTTL time.Duration
}

// IssuerConfig configures signing.
type IssuerConfig struct {
	// PrivateKeyPEM is a PKCS#8 or SEC1 EC private key, P-256.
	//
	// ES256 rather than RS256: the tokens are verified on every request by
	// every service, and a P-256 signature is 64 bytes against RSA-2048's
	// 256, which matters when the token rides in a header on every call.
	PrivateKeyPEM string
	KeyID         string
	Issuer        string
	Audience      string
	AccessTTL     time.Duration
	RefreshTTL    time.Duration
}

// NewIssuer parses the signing key.
func NewIssuer(c IssuerConfig) (*Issuer, error) {
	key, err := parseECPrivateKey(c.PrivateKeyPEM)
	if err != nil {
		return nil, err
	}
	if c.KeyID == "" {
		return nil, errors.New("authn: key id is required for rotation")
	}
	return &Issuer{
		key:        key,
		keyID:      c.KeyID,
		issuer:     orDefault(c.Issuer, "messaging"),
		audience:   orDefault(c.Audience, "messaging-api"),
		accessTTL:  orDefaultDur(c.AccessTTL, 15*time.Minute),
		refreshTTL: orDefaultDur(c.RefreshTTL, 60*24*time.Hour),
	}, nil
}

// Issue mints a token pair for a session.
func (i *Issuer) Issue(userID, deviceID int64, scopes []string) (access string, refresh string, expiresIn int, err error) {
	now := time.Now()

	access, err = i.sign(Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    i.issuer,
			Audience:  jwt.ClaimStrings{i.audience},
			Subject:   fmt.Sprint(userID),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now.Add(-30 * time.Second)), // small clock skew allowance
			ExpiresAt: jwt.NewNumericDate(now.Add(i.accessTTL)),
			ID:        randomJTI(),
		},
		Type: AccessToken, UserID: userID, DeviceID: deviceID, Scopes: scopes,
	})
	if err != nil {
		return "", "", 0, err
	}

	refresh, err = i.sign(Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    i.issuer,
			Audience:  jwt.ClaimStrings{i.issuer + ":refresh"},
			Subject:   fmt.Sprint(userID),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(i.refreshTTL)),
			ID:        randomJTI(),
		},
		Type: RefreshToken, UserID: userID, DeviceID: deviceID,
	})
	if err != nil {
		return "", "", 0, err
	}

	return access, refresh, int(i.accessTTL.Seconds()), nil
}

func (i *Issuer) sign(c Claims) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodES256, c)
	t.Header["kid"] = i.keyID
	s, err := t.SignedString(i.key)
	if err != nil {
		return "", fmt.Errorf("authn: sign: %w", err)
	}
	return s, nil
}

// PublicJWKS renders the issuer's public key as a JWKS document, served at
// /.well-known/jwks.json so verifiers can refresh keys without a redeploy.
func (i *Issuer) PublicJWKS() ([]byte, error) {
	pub := i.key.PublicKey
	byteLen := (pub.Curve.Params().BitSize + 7) / 8
	x := pub.X.Bytes()
	y := pub.Y.Bytes()
	// Pad to the fixed coordinate length; a short leading byte would produce
	// a JWKS that some strict verifiers reject.
	xb := make([]byte, byteLen)
	yb := make([]byte, byteLen)
	copy(xb[byteLen-len(x):], x)
	copy(yb[byteLen-len(y):], y)

	doc := map[string]any{
		"keys": []map[string]string{{
			"kty": "EC",
			"crv": "P-256",
			"alg": "ES256",
			"use": "sig",
			"kid": i.keyID,
			"x":   base64.RawURLEncoding.EncodeToString(xb),
			"y":   base64.RawURLEncoding.EncodeToString(yb),
		}},
	}
	return json.Marshal(doc)
}

// Verifier validates tokens against one or more public keys.
type Verifier struct {
	keys     map[string]*ecdsa.PublicKey
	issuer   string
	audience string
}

// NewVerifier builds a verifier from a JWKS document.
func NewVerifier(jwks []byte, issuer, audience string) (*Verifier, error) {
	var doc struct {
		Keys []struct {
			Kid string `json:"kid"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(jwks, &doc); err != nil {
		return nil, fmt.Errorf("authn: parse JWKS: %w", err)
	}
	if len(doc.Keys) == 0 {
		return nil, errors.New("authn: JWKS contains no keys")
	}

	keys := make(map[string]*ecdsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Crv != "P-256" {
			continue
		}
		xb, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, fmt.Errorf("authn: JWKS key %s: bad x: %w", k.Kid, err)
		}
		yb, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			return nil, fmt.Errorf("authn: JWKS key %s: bad y: %w", k.Kid, err)
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P256()}
		pub.X = bigFromBytes(xb)
		pub.Y = bigFromBytes(yb)
		if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
			return nil, fmt.Errorf("authn: JWKS key %s is not on P-256", k.Kid)
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return nil, errors.New("authn: JWKS contains no usable P-256 keys")
	}

	return &Verifier{
		keys:     keys,
		issuer:   orDefault(issuer, "messaging"),
		audience: orDefault(audience, "messaging-api"),
	}, nil
}

// NewVerifierFromIssuer is the single-process shortcut used by the auth
// service, which both signs and verifies.
func NewVerifierFromIssuer(i *Issuer) (*Verifier, error) {
	jwks, err := i.PublicJWKS()
	if err != nil {
		return nil, err
	}
	return NewVerifier(jwks, i.issuer, i.audience)
}

// Verify parses and validates an access token.
func (v *Verifier) Verify(raw string, want TokenType) (*Claims, error) {
	if raw == "" {
		return nil, ErrNoToken
	}

	audience := v.audience
	if want == RefreshToken {
		audience = v.issuer + ":refresh"
	}

	var claims Claims
	_, err := jwt.ParseWithClaims(raw, &claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		key, ok := v.keys[kid]
		if !ok {
			return nil, fmt.Errorf("unknown key id %q", kid)
		}
		return key, nil
	},
		// Pinning the algorithm is what stops the classic "alg: none" and
		// HMAC-with-the-public-key confusion attacks.
		jwt.WithValidMethods([]string{jwt.SigningMethodES256.Alg()}),
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(audience),
		jwt.WithLeeway(30*time.Second),
	)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpired
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if claims.Type != want {
		return nil, ErrWrongType
	}
	if claims.UserID == 0 {
		return nil, fmt.Errorf("%w: no subject", ErrInvalidToken)
	}
	return &claims, nil
}

// ---------------------------------------------------------------------------
// HTTP middleware
// ---------------------------------------------------------------------------

type ctxKey struct{}

var claimsKey ctxKey

// TokenVerifier is what the middleware needs from a verifier.
//
// It exists so a handler chain can be wired with either a static Verifier or
// a RefreshingVerifier that swaps its key set underneath, without the
// middleware knowing or caring which.
type TokenVerifier interface {
	Verify(raw string, want TokenType) (*Claims, error)
}

// Middleware rejects unauthenticated requests and stores the claims.
func Middleware(v TokenVerifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := BearerToken(r)
			claims, err := v.Verify(raw, AccessToken)
			if err != nil {
				switch {
				case errors.Is(err, ErrNoToken):
					httpx.WriteError(w, r, httpx.ErrUnauthorized("authorization required"))
				case errors.Is(err, ErrExpired):
					httpx.WriteError(w, r, httpx.ErrUnauthorized("access token expired"))
				default:
					httpx.WriteError(w, r, httpx.ErrUnauthorized("invalid access token"))
				}
				return
			}
			next.ServeHTTP(w, r.WithContext(WithClaims(r.Context(), claims)))
		})
	}
}

// BearerToken extracts the credential from the Authorization header.
func BearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" {
		return ""
	}
	scheme, token, ok := strings.Cut(h, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(token)
}

// WithClaims stores claims on a context.
func WithClaims(ctx context.Context, c *Claims) context.Context {
	return context.WithValue(ctx, claimsKey, c)
}

// ClaimsFrom reads claims off a context.
func ClaimsFrom(ctx context.Context) (*Claims, bool) {
	c, ok := ctx.Value(claimsKey).(*Claims)
	return c, ok && c != nil
}

// MustUserID returns the authenticated user id or an API error.
func MustUserID(ctx context.Context) (int64, error) {
	c, ok := ClaimsFrom(ctx)
	if !ok {
		return 0, httpx.ErrUnauthorized("authorization required")
	}
	return c.UserID, nil
}

// ---------------------------------------------------------------------------
// Key helpers
// ---------------------------------------------------------------------------

func parseECPrivateKey(pemStr string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(pemStr)))
	if block == nil {
		return nil, errors.New("authn: private key is not valid PEM")
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("authn: parse private key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("authn: expected an EC private key, got %T", parsed)
	}
	if key.Curve != elliptic.P256() {
		return nil, errors.New("authn: signing key must use curve P-256")
	}
	return key, nil
}

// GenerateSigningKey produces a fresh P-256 key in PKCS#8 PEM. Used by the
// bootstrap script that seeds Secret Manager and by local development.
func GenerateSigningKey() (string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("authn: generate key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("authn: marshal key: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

func randomJTI() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func orDefaultDur(v, def time.Duration) time.Duration {
	if v == 0 {
		return def
	}
	return v
}
