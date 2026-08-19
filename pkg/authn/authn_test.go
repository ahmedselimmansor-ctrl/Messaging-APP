package authn

import (
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// This package decides who every request is. A defect here is not a bug in a
// feature, it is a way into every account — so the tests below are mostly
// about what must be *refused*.

func newTestIssuer(t *testing.T) *Issuer {
	t.Helper()
	pem, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	iss, err := NewIssuer(IssuerConfig{
		PrivateKeyPEM: pem,
		KeyID:         "test-key",
		Issuer:        "test-issuer",
		Audience:      "test-audience",
		AccessTTL:     15 * time.Minute,
		RefreshTTL:    60 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	return iss
}

func newPair(t *testing.T) (*Issuer, *Verifier) {
	t.Helper()
	iss := newTestIssuer(t)
	v, err := NewVerifierFromIssuer(iss)
	if err != nil {
		t.Fatal(err)
	}
	return iss, v
}

func TestIssueAndVerifyRoundTrip(t *testing.T) {
	iss, v := newPair(t)

	access, refresh, expiresIn, err := iss.Issue(42, 7, []string{"read"})
	if err != nil {
		t.Fatal(err)
	}
	if expiresIn <= 0 {
		t.Errorf("expiresIn = %d, want positive", expiresIn)
	}

	claims, err := v.Verify(access, AccessToken)
	if err != nil {
		t.Fatalf("a freshly issued access token does not verify: %v", err)
	}
	if claims.UserID != 42 || claims.DeviceID != 7 {
		t.Errorf("identity did not survive the round trip: uid=%d did=%d", claims.UserID, claims.DeviceID)
	}
	if !claims.HasScope("read") {
		t.Error("scopes did not survive the round trip")
	}

	if _, err := v.Verify(refresh, RefreshToken); err != nil {
		t.Fatalf("a freshly issued refresh token does not verify: %v", err)
	}
}

// The two token types must not be interchangeable. If an access token were
// accepted where a refresh token is expected, a 15-minute credential would
// become a 60-day one; the reverse would let a stolen refresh token be used
// directly against the API.

func TestAccessTokenIsRejectedAsRefresh(t *testing.T) {
	iss, v := newPair(t)
	access, _, _, err := iss.Issue(1, 1, nil)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := v.Verify(access, RefreshToken); err == nil {
		t.Fatal("an access token was accepted where a refresh token was required")
	}
}

func TestRefreshTokenIsRejectedAsAccess(t *testing.T) {
	iss, v := newPair(t)
	_, refresh, _, err := iss.Issue(1, 1, nil)
	if err != nil {
		t.Fatal(err)
	}

	// The separate audience is what rejects this in practice, so the failure
	// arrives as an audience mismatch rather than a type mismatch. The `typ`
	// claim is checked independently — see
	// TestTypeClaimIsCheckedIndependentlyOfTheAudience, which isolates it.
	if _, err := v.Verify(refresh, AccessToken); err == nil {
		t.Fatal("a refresh token was accepted on the access path")
	}
}

// Algorithm confusion. These are the attacks that have broken real JWT
// deployments.
//
// Two independent things stop them here, and it is worth being precise about
// which does the work: Verifier.keys is a map[string]*ecdsa.PublicKey, so an
// HMAC method cannot even accept the key it is handed, and jwt.WithValidMethods
// rejects a non-ES256 alg before the key is looked up at all. Removing either
// one alone leaves these tests passing — they assert the behaviour, which is
// what matters, not one particular line of the implementation.

func TestUnsignedTokenIsRejected(t *testing.T) {
	iss, v := newPair(t)

	// alg: none, with claims that would otherwise be perfectly valid.
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "test-issuer",
			Audience:  jwt.ClaimStrings{"test-audience"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Type:   AccessToken,
		UserID: 999,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	tok.Header["kid"] = "test-key"
	raw, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	_ = iss

	if _, err := v.Verify(raw, AccessToken); err == nil {
		t.Fatal("an unsigned token was accepted — this is a complete authentication bypass")
	}
}

func TestHMACSignedWithThePublicKeyIsRejected(t *testing.T) {
	// The classic confusion attack: take the verifier's *public* key, use it
	// as an HMAC secret, and claim alg: HS256. Where a verifier selects the
	// algorithm from the header and stores keys loosely typed, the public key
	// it already holds validates the signature and anyone can mint tokens.
	iss, v := newPair(t)

	jwks, err := iss.PublicJWKS()
	if err != nil {
		t.Fatal(err)
	}

	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "test-issuer",
			Audience:  jwt.ClaimStrings{"test-audience"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Type:   AccessToken,
		UserID: 999,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tok.Header["kid"] = "test-key"
	raw, err := tok.SignedString(jwks) // the public material as the HMAC secret
	if err != nil {
		t.Fatal(err)
	}

	if _, err := v.Verify(raw, AccessToken); err == nil {
		t.Fatal("an HS256 token was accepted by an ES256 verifier — algorithm confusion")
	}
}

func TestTokenFromADifferentKeyIsRejected(t *testing.T) {
	// Two independent issuers. A token from one must be worthless to the
	// other, or a compromised staging key would mint production credentials.
	_, v := newPair(t)
	other := newTestIssuer(t)

	access, _, _, err := other.Issue(1, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(access, AccessToken); err == nil {
		t.Fatal("a token signed by an unrelated key was accepted")
	}
}

func TestTamperedPayloadIsRejected(t *testing.T) {
	iss, v := newPair(t)
	access, _, _, err := iss.Issue(1, 1, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Rewrite the user id in the payload and re-assemble with the original
	// signature — what an attacker with a valid token of their own would try.
	parts := strings.Split(access, ".")
	if len(parts) != 3 {
		t.Fatalf("expected three JWT segments, got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(payload, &m); err != nil {
		t.Fatal(err)
	}
	m["uid"] = 999999
	repacked, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	forged := parts[0] + "." + base64.RawURLEncoding.EncodeToString(repacked) + "." + parts[2]

	if _, err := v.Verify(forged, AccessToken); err == nil {
		t.Fatal("a token whose user id was rewritten was accepted")
	}
}

func TestExpiredTokenIsRejectedAsExpired(t *testing.T) {
	// A distinct error, because the client's correct response differs: refresh
	// on expiry, re-authenticate on anything else.
	pem, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	iss, err := NewIssuer(IssuerConfig{
		PrivateKeyPEM: pem,
		KeyID:         "test-key",
		Issuer:        "test-issuer",
		Audience:      "test-audience",
		// Well beyond the verifier's 30-second leeway.
		AccessTTL:  -10 * time.Minute,
		RefreshTTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewVerifierFromIssuer(iss)
	if err != nil {
		t.Fatal(err)
	}

	access, _, _, err := iss.Issue(1, 1, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = v.Verify(access, AccessToken)
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("Verify returned %v, want ErrExpired — the client cannot tell it should refresh", err)
	}
}

func TestWrongIssuerIsRejected(t *testing.T) {
	pem, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	iss, err := NewIssuer(IssuerConfig{
		PrivateKeyPEM: pem, KeyID: "test-key",
		Issuer: "somebody-else", Audience: "test-audience",
		AccessTTL: time.Hour, RefreshTTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	access, _, _, err := iss.Issue(1, 1, nil)
	if err != nil {
		t.Fatal(err)
	}

	// A verifier that trusts the same key but a different issuer name.
	sameKey, err := NewIssuer(IssuerConfig{
		PrivateKeyPEM: pem, KeyID: "test-key",
		Issuer: "test-issuer", Audience: "test-audience",
		AccessTTL: time.Hour, RefreshTTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewVerifierFromIssuer(sameKey)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := v.Verify(access, AccessToken); err == nil {
		t.Fatal("a token from a different issuer was accepted despite a matching key")
	}
}

func TestEmptyTokenIsRejected(t *testing.T) {
	_, v := newPair(t)
	if _, err := v.Verify("", AccessToken); !errors.Is(err, ErrNoToken) {
		t.Errorf("Verify(\"\") = %v, want ErrNoToken", err)
	}
}

func TestGarbageIsRejected(t *testing.T) {
	_, v := newPair(t)
	for _, raw := range []string{
		"not-a-jwt",
		"a.b.c",
		"...",
		strings.Repeat("A", 4096),
	} {
		if _, err := v.Verify(raw, AccessToken); err == nil {
			t.Errorf("Verify(%.20q) succeeded, want an error", raw)
		}
	}
}

func TestUnknownKeyIDIsRejected(t *testing.T) {
	iss, v := newPair(t)
	access, _, _, err := iss.Issue(1, 1, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Repoint the kid at a key the verifier does not hold. The signature is
	// still genuine, so only the kid lookup can reject this.
	parts := strings.Split(access, ".")
	hdr, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(hdr, &m); err != nil {
		t.Fatal(err)
	}
	m["kid"] = "some-other-key"
	repacked, _ := json.Marshal(m)
	forged := base64.RawURLEncoding.EncodeToString(repacked) + "." + parts[1] + "." + parts[2]

	if _, err := v.Verify(forged, AccessToken); err == nil {
		t.Fatal("a token naming an unknown key id was accepted")
	}
}

func TestPublicJWKSCarriesNoPrivateMaterial(t *testing.T) {
	// This document is served publicly at /.well-known/jwks.json. A private
	// component leaking into it hands over the ability to mint tokens.
	iss := newTestIssuer(t)
	jwks, err := iss.PublicJWKS()
	if err != nil {
		t.Fatal(err)
	}

	var doc struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(jwks, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Keys) == 0 {
		t.Fatal("the JWKS document contains no keys")
	}
	for i, k := range doc.Keys {
		// "d" is the EC private scalar. Its presence would be catastrophic.
		if _, bad := k["d"]; bad {
			t.Errorf("key %d exposes the private scalar 'd' in the public JWKS", i)
		}
		if k["kty"] != "EC" || k["crv"] != "P-256" {
			t.Errorf("key %d is %v/%v, want EC/P-256", i, k["kty"], k["crv"])
		}
		if k["x"] == nil || k["y"] == nil {
			t.Errorf("key %d is missing its public coordinates", i)
		}
	}
}

func TestVerifierBuiltFromPublishedJWKSAccepts(t *testing.T) {
	// The real deployment path: services fetch the JWKS over HTTP and build a
	// verifier from it. If that document were not sufficient, every service
	// would need the private key.
	iss := newTestIssuer(t)
	jwks, err := iss.PublicJWKS()
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewVerifier(jwks, "test-issuer", "test-audience")
	if err != nil {
		t.Fatal(err)
	}

	access, _, _, err := iss.Issue(5, 6, nil)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := v.Verify(access, AccessToken)
	if err != nil {
		t.Fatalf("a verifier built from the published JWKS rejected a valid token: %v", err)
	}
	if claims.UserID != 5 {
		t.Errorf("uid = %d, want 5", claims.UserID)
	}
}

func TestIssuerRejectsANonECKey(t *testing.T) {
	// ES256 is pinned end to end. An RSA key would silently change the
	// algorithm the whole platform verifies with.
	_, err := NewIssuer(IssuerConfig{
		PrivateKeyPEM: "-----BEGIN PRIVATE KEY-----\nbm90IGEga2V5\n-----END PRIVATE KEY-----",
		KeyID:         "k", Issuer: "i", Audience: "a",
	})
	if err == nil {
		t.Fatal("NewIssuer accepted material that is not an EC private key")
	}
}

func TestEachTokenHasAUniqueID(t *testing.T) {
	// The jti is what makes a token individually revocable later. Two tokens
	// sharing one would make a future denylist revoke more than intended.
	iss := newTestIssuer(t)
	seen := make(map[string]bool)
	for i := 0; i < 200; i++ {
		access, _, _, err := iss.Issue(1, 1, nil)
		if err != nil {
			t.Fatal(err)
		}
		parts := strings.Split(access, ".")
		payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
		var m map[string]any
		if err := json.Unmarshal(payload, &m); err != nil {
			t.Fatal(err)
		}
		jti, _ := m["jti"].(string)
		if jti == "" {
			t.Fatal("issued a token with no jti")
		}
		if seen[jti] {
			t.Fatalf("jti %q was issued twice", jti)
		}
		seen[jti] = true
	}
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

func TestMiddlewareRejectsMissingAndBadCredentials(t *testing.T) {
	iss, v := newPair(t)
	access, _, _, err := iss.Issue(11, 22, nil)
	if err != nil {
		t.Fatal(err)
	}

	reached := false
	h := Middleware(v)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		claims, ok := ClaimsFrom(r.Context())
		if !ok || claims.UserID != 11 {
			t.Error("the handler did not receive the caller's claims")
		}
	}))

	cases := []struct {
		name       string
		header     string
		wantCalled bool
	}{
		{"no header", "", false},
		{"not bearer", "Basic dXNlcjpwYXNz", false},
		{"bearer with nothing", "Bearer ", false},
		{"bearer garbage", "Bearer not.a.token", false},
		{"valid", "Bearer " + access, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reached = false
			r := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
			if tc.header != "" {
				r.Header.Set("Authorization", tc.header)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)

			if reached != tc.wantCalled {
				t.Errorf("handler reached = %v, want %v (status %d)", reached, tc.wantCalled, w.Code)
			}
			if !tc.wantCalled && w.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", w.Code)
			}
		})
	}
}

func TestMiddlewareRejectsARefreshTokenOnTheAPI(t *testing.T) {
	// A refresh token is a 60-day credential. Accepting one as a bearer token
	// on the API would defeat the whole reason for having two types.
	iss, v := newPair(t)
	_, refresh, _, err := iss.Issue(1, 1, nil)
	if err != nil {
		t.Fatal(err)
	}

	called := false
	h := Middleware(v)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))

	r := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
	r.Header.Set("Authorization", "Bearer "+refresh)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if called {
		t.Fatal("a refresh token was accepted as an API bearer token")
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestBearerTokenParsing(t *testing.T) {
	cases := map[string]string{
		"Bearer abc":  "abc",
		"bearer abc":  "abc",
		"BEARER abc":  "abc",
		"Bearer  abc": "abc",
		"Basic abc":   "",
		"abc":         "",
		"":            "",
		"Bearer":      "",
	}
	for header, want := range cases {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		if header != "" {
			r.Header.Set("Authorization", header)
		}
		if got := BearerToken(r); got != want {
			t.Errorf("BearerToken(%q) = %q, want %q", header, got, want)
		}
	}
}

func TestMustUserIDRequiresClaims(t *testing.T) {
	// A handler that reaches this without claims has been mounted outside the
	// middleware. Returning an error rather than zero is what stops that
	// becoming "user 0 owns everything".
	if _, err := MustUserID(httptest.NewRequest(http.MethodGet, "/", nil).Context()); err == nil {
		t.Fatal("MustUserID succeeded on a context with no claims")
	}
}

func TestClaimsWithNoScopesHaveFullPrivileges(t *testing.T) {
	// The documented convention. If it were inverted, every normal mobile
	// session would be denied everything.
	c := &Claims{}
	if !c.HasScope("anything") {
		t.Error("an empty scope list should mean full privileges")
	}

	limited := &Claims{Scopes: []string{"read"}}
	if !limited.HasScope("read") {
		t.Error("a granted scope was not recognised")
	}
	if limited.HasScope("write") {
		t.Error("a scope that was not granted was accepted")
	}
}

func TestGeneratedKeyIsUsableP256(t *testing.T) {
	pem, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	key, err := parseECPrivateKey(pem)
	if err != nil {
		t.Fatalf("the generated key does not parse: %v", err)
	}
	if key.Curve != elliptic.P256() {
		t.Errorf("curve = %v, want P-256", key.Curve.Params().Name)
	}

	// Two calls must not produce the same key.
	other, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	if pem == other {
		t.Fatal("GenerateSigningKey returned the same key twice")
	}
}

func TestVerifyIsSafeConcurrently(t *testing.T) {
	// Every service verifies on every request from many goroutines at once. A
	// data race here would be a heisenbug in the authentication path, which is
	// the worst place to have one.
	iss, v := newPair(t)
	access, _, _, err := iss.Issue(3, 4, nil)
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 64)
	for i := 0; i < 64; i++ {
		go func() {
			_, err := v.Verify(access, AccessToken)
			done <- err
		}()
	}
	for i := 0; i < 64; i++ {
		if err := <-done; err != nil {
			t.Fatalf("concurrent verify failed: %v", err)
		}
	}
}

// The two tests above are satisfied by the audience separation alone, which
// means the `typ` claim check in Verify has no coverage from them. These
// isolate it: the token is signed by the real key, names the real issuer, and
// carries the *correct* audience for the path it is presented on. Only the
// claim itself is wrong.
//
// This matters because the audience strings are configuration. If a
// deployment ever set the access and refresh audiences to the same value, the
// separation would silently stop working and this check would be all that is
// left.

func signAs(t *testing.T, pemKey, kid, issuer, audience string, c Claims) string {
	t.Helper()
	key, err := parseECPrivateKey(pemKey)
	if err != nil {
		t.Fatal(err)
	}
	c.Issuer = issuer
	c.Audience = jwt.ClaimStrings{audience}
	if c.ExpiresAt == nil {
		c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(time.Hour))
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, c)
	tok.Header["kid"] = kid
	raw, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func issuerWithKey(t *testing.T) (*Issuer, *Verifier, string) {
	t.Helper()
	pem, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	iss, err := NewIssuer(IssuerConfig{
		PrivateKeyPEM: pem, KeyID: "test-key",
		Issuer: "test-issuer", Audience: "test-audience",
		AccessTTL: time.Hour, RefreshTTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewVerifierFromIssuer(iss)
	if err != nil {
		t.Fatal(err)
	}
	return iss, v, pem
}

func TestTypeClaimIsCheckedIndependentlyOfTheAudience(t *testing.T) {
	_, v, pem := issuerWithKey(t)

	// Correct signature, correct issuer, correct *access* audience — and typ
	// says refresh. Nothing but the type check can reject this.
	raw := signAs(t, pem, "test-key", "test-issuer", "test-audience", Claims{
		Type:   RefreshToken,
		UserID: 1,
	})

	_, err := v.Verify(raw, AccessToken)
	if !errors.Is(err, ErrWrongType) {
		t.Fatalf("Verify accepted a token whose typ claim says refresh on the access path: err = %v", err)
	}
}

func TestTypeClaimMustNotBeAbsent(t *testing.T) {
	// An omitted typ is not the same as a matching one. A token minted by a
	// future version that forgot the field must not be treated as an access
	// token by default.
	_, v, pem := issuerWithKey(t)
	raw := signAs(t, pem, "test-key", "test-issuer", "test-audience", Claims{UserID: 1})

	if _, err := v.Verify(raw, AccessToken); !errors.Is(err, ErrWrongType) {
		t.Fatalf("a token with no typ claim was accepted as an access token: err = %v", err)
	}
}

func TestTokenWithNoSubjectIsRejected(t *testing.T) {
	// uid 0 is the zero value, so a token that simply omits it would otherwise
	// authenticate as "user 0" — and any handler keyed on the caller's id
	// would then read and write a shared phantom account.
	_, v, pem := issuerWithKey(t)
	raw := signAs(t, pem, "test-key", "test-issuer", "test-audience", Claims{
		Type: AccessToken, // valid in every respect except the subject
	})

	if _, err := v.Verify(raw, AccessToken); err == nil {
		t.Fatal("a token carrying no user id was accepted — it would authenticate as user 0")
	}
}

func TestES384TokenIsRejected(t *testing.T) {
	// A stronger curve is still the wrong one. The platform verifies ES256
	// everywhere, and accepting anything else would mean the algorithm is
	// attacker-influenced rather than fixed.
	_, v, pem := issuerWithKey(t)
	key, err := parseECPrivateKey(pem)
	if err != nil {
		t.Fatal(err)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES384, Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "test-issuer",
			Audience:  jwt.ClaimStrings{"test-audience"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Type: AccessToken, UserID: 1,
	})
	tok.Header["kid"] = "test-key"
	// Signing a P-256 key with ES384 fails in the library, which is itself the
	// point: there is no way to produce such a token against this key. Assert
	// that, rather than pretending to verify something unproducible.
	if _, err := tok.SignedString(key); err == nil {
		t.Fatal("an ES384 signature over a P-256 key was produced; the curve check is not holding")
	}
	_ = v
}
