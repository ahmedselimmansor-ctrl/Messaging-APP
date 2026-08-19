package chat

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/pervagans/messaging-app/pkg/authn"
	"github.com/pervagans/messaging-app/pkg/httpx"
)

// Route authentication coverage.
//
// Two kinds of check, because they catch different things and one alone is
// not enough:
//
//   - The behavioural sweeps below walk every route chi actually registered
//     and assert none of them serves an anonymous or badly-credentialled
//     request. A new endpoint is covered automatically; there is no list to
//     forget to update.
//   - TestEveryPublicRouteCarriesTheAuthenticationMiddleware, at the bottom,
//     checks the middleware chain structurally.
//
// The second exists because the first is not sufficient, which was established
// by mutation rather than assumed: moving a route out of the authenticated
// group leaves every behavioural sweep passing, since each handler also calls
// ClaimsFrom and returns 401 by itself. That defence-in-depth is welcome, and
// it is exactly what hides the misplaced line.

// routerFor builds a Service with only what Routes() itself dereferences.
//
// The repositories stay nil deliberately. Every request in this file is
// expected to be rejected before a handler touches one, so a nil-pointer panic
// is itself a finding: it means the request reached business logic it should
// never have reached.
func routerFor(t *testing.T) http.Handler {
	t.Helper()

	pem, err := authn.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	iss, err := authn.NewIssuer(authn.IssuerConfig{
		PrivateKeyPEM: pem, KeyID: "test", Issuer: "test", Audience: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	v, err := authn.NewVerifierFromIssuer(iss)
	if err != nil {
		t.Fatal(err)
	}

	s := &Service{Verifier: v}
	s.Init()
	return s.Routes()
}

// walkRoutes returns every (method, path) chi has registered.
func walkRoutes(t *testing.T, h http.Handler) []struct{ Method, Path string } {
	t.Helper()

	router, ok := h.(chi.Routes)
	if !ok {
		t.Fatalf("Routes() returned %T, which cannot be walked", h)
	}

	var out []struct{ Method, Path string }
	err := chi.Walk(router, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		out = append(out, struct{ Method, Path string }{method, route})
		return nil
	})
	if err != nil {
		t.Fatalf("walking the routes: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("no routes were registered; this test would pass vacuously")
	}
	return out
}

// concrete replaces chi's {param} placeholders with values that parse, so a
// request reaches the authentication layer rather than failing on the path.
func concrete(route string) string {
	r := strings.NewReplacer(
		"{chatID}", "1",
		"{userID}", "2",
		"{seq}", "3",
		"{deviceID}", "4",
		"{uploadID}", "5",
		"{reportID}", "6",
	)
	return r.Replace(route)
}

func TestEveryPublicRouteRequiresAuthentication(t *testing.T) {
	h := routerFor(t)
	routes := walkRoutes(t, h)

	checked := 0
	for _, rt := range routes {
		if !strings.HasPrefix(rt.Path, "/v1/") {
			continue // /internal is covered separately below
		}
		checked++

		t.Run(rt.Method+" "+rt.Path, func(t *testing.T) {
			req := httptest.NewRequest(rt.Method, concrete(rt.Path), strings.NewReader("{}"))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			// A panic here means the request reached a handler that
			// dereferenced a repository — i.e. it was not rejected in time.
			defer func() {
				if p := recover(); p != nil {
					t.Fatalf("an unauthenticated request reached business logic and panicked (%v) — "+
						"this route is almost certainly mounted outside the authentication group", p)
				}
			}()

			h.ServeHTTP(w, req)

			if w.Code != http.StatusUnauthorized {
				t.Errorf("an unauthenticated request returned %d, want 401 — "+
					"this route may be mounted outside the authentication group", w.Code)
			}
		})
	}

	if checked == 0 {
		t.Fatal("no /v1 routes were checked; the prefix filter is wrong and this test proves nothing")
	}
	t.Logf("checked %d public routes", checked)
}

func TestEveryPublicRouteRejectsAGarbageToken(t *testing.T) {
	// The same sweep with a credential present but invalid. A route that
	// verified nothing would let this through where the anonymous case
	// happened to be caught by something else.
	h := routerFor(t)

	for _, rt := range walkRoutes(t, h) {
		if !strings.HasPrefix(rt.Path, "/v1/") {
			continue
		}
		t.Run(rt.Method+" "+rt.Path, func(t *testing.T) {
			req := httptest.NewRequest(rt.Method, concrete(rt.Path), strings.NewReader("{}"))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer not.a.real.token")
			w := httptest.NewRecorder()

			defer func() {
				if p := recover(); p != nil {
					t.Fatalf("a request with an invalid token reached business logic and panicked: %v", p)
				}
			}()

			h.ServeHTTP(w, req)

			if w.Code != http.StatusUnauthorized {
				t.Errorf("an invalid token returned %d, want 401", w.Code)
			}
		})
	}
}

func TestInternalRoutesRequireAnIdentityHeader(t *testing.T) {
	// /internal trusts X-User-Id because the mesh policy restricts those paths
	// to the gateway. It must still refuse a request that asserts no identity
	// at all, or a misrouted call would be handled as user 0.
	h := routerFor(t)

	checked := 0
	for _, rt := range walkRoutes(t, h) {
		if !strings.HasPrefix(rt.Path, "/internal/") {
			continue
		}
		checked++

		t.Run(rt.Method+" "+rt.Path, func(t *testing.T) {
			req := httptest.NewRequest(rt.Method, concrete(rt.Path), strings.NewReader("{}"))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			defer func() {
				if p := recover(); p != nil {
					t.Fatalf("an internal request with no identity reached business logic: %v", p)
				}
			}()

			h.ServeHTTP(w, req)

			if w.Code != http.StatusUnauthorized {
				t.Errorf("an internal request with no X-User-Id returned %d, want 401", w.Code)
			}
		})
	}

	if checked == 0 {
		t.Fatal("no /internal routes were found; this test proves nothing")
	}
}

func TestInternalRoutesRejectAZeroUserID(t *testing.T) {
	// X-User-Id: 0 is the shape a buggy caller sends. Treating it as valid
	// would authenticate every such request as a shared phantom account.
	h := routerFor(t)

	for _, rt := range walkRoutes(t, h) {
		if !strings.HasPrefix(rt.Path, "/internal/") {
			continue
		}
		t.Run(rt.Method+" "+rt.Path, func(t *testing.T) {
			req := httptest.NewRequest(rt.Method, concrete(rt.Path), strings.NewReader("{}"))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-User-Id", "0")
			w := httptest.NewRecorder()

			defer func() {
				if p := recover(); p != nil {
					t.Fatalf("an internal request claiming user 0 reached business logic: %v", p)
				}
			}()

			h.ServeHTTP(w, req)

			if w.Code != http.StatusUnauthorized {
				t.Errorf("X-User-Id: 0 returned %d, want 401", w.Code)
			}
		})
	}
}

func TestPublicRoutesDoNotAcceptTheInternalIdentityHeader(t *testing.T) {
	// The header that authenticates an internal call must be worthless on the
	// public surface. If a /v1 route honoured it, anyone on the internet could
	// assert any identity by setting one header — the single worst bug this
	// architecture could have.
	h := routerFor(t)

	for _, rt := range walkRoutes(t, h) {
		if !strings.HasPrefix(rt.Path, "/v1/") {
			continue
		}
		t.Run(rt.Method+" "+rt.Path, func(t *testing.T) {
			req := httptest.NewRequest(rt.Method, concrete(rt.Path), strings.NewReader("{}"))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-User-Id", "1")
			req.Header.Set("X-Device-Id", "1")
			w := httptest.NewRecorder()

			defer func() {
				if p := recover(); p != nil {
					t.Fatalf("a public request carrying X-User-Id reached business logic (%v) — "+
						"the internal identity header is being honoured on the public surface", p)
				}
			}()

			h.ServeHTTP(w, req)

			if w.Code != http.StatusUnauthorized {
				t.Errorf("a public route accepted X-User-Id as authentication (status %d) — "+
					"anyone could impersonate any account", w.Code)
			}
		})
	}
}

// The sweeps above assert end-to-end behaviour: no public route serves an
// anonymous request. That is worth having, but it does NOT prove the
// authentication middleware is mounted — every handler also calls ClaimsFrom
// and returns 401 on its own, so a route accidentally mounted outside the
// group still answers 401 and the sweeps stay green.
//
// Verified by mutation: moving /v1/me/export out of the authenticated group
// leaves every test above passing.
//
// So this checks the structure instead. chi.Walk reports the middleware chain
// attached to each route, and a route inside the group carries exactly one
// more than the router's base chain. That difference is the thing that cannot
// be faked by a handler being careful.

// middlewareCounts returns the chain length chi recorded for each route.
func middlewareCounts(t *testing.T, h http.Handler) map[string]int {
	t.Helper()

	router, ok := h.(chi.Routes)
	if !ok {
		t.Fatalf("Routes() returned %T, which cannot be walked", h)
	}

	out := make(map[string]int)
	err := chi.Walk(router, func(method, route string, _ http.Handler, mws ...func(http.Handler) http.Handler) error {
		out[method+" "+route] = len(mws)
		return nil
	})
	if err != nil {
		t.Fatalf("walking the routes: %v", err)
	}
	return out
}

func TestEveryPublicRouteCarriesTheAuthenticationMiddleware(t *testing.T) {
	base := len(httpx.BaseMiddleware("chat-service"))
	counts := middlewareCounts(t, routerFor(t))

	checked := 0
	for route, n := range counts {
		if !strings.HasPrefix(route[strings.Index(route, " ")+1:], "/v1/") {
			continue
		}
		checked++

		// Base chain plus the group's authentication middleware.
		if n <= base {
			t.Errorf("%s has %d middlewares against a base chain of %d — "+
				"it is mounted OUTSIDE the authentication group. It may still answer 401 "+
				"because its handler checks claims itself, which is why the behavioural "+
				"sweeps do not catch this.", route, n, base)
		}
	}

	if checked == 0 {
		t.Fatal("no /v1 routes were checked; this test proves nothing")
	}
}

func TestEveryInternalRouteCarriesTheIdentityMiddleware(t *testing.T) {
	base := len(httpx.BaseMiddleware("chat-service"))
	counts := middlewareCounts(t, routerFor(t))

	checked := 0
	for route, n := range counts {
		if !strings.HasPrefix(route[strings.Index(route, " ")+1:], "/internal/") {
			continue
		}
		checked++

		if n <= base {
			t.Errorf("%s has %d middlewares against a base chain of %d — "+
				"it is mounted outside the internal-identity group", route, n, base)
		}
	}

	if checked == 0 {
		t.Fatal("no /internal routes were checked; this test proves nothing")
	}
}

func TestAllPublicRoutesShareOneMiddlewareChain(t *testing.T) {
	// A route with a different chain length than its siblings is mounted in a
	// different group. That is not necessarily wrong, but it is never
	// accidental — and here there is only one group, so any variation is a
	// mistake.
	counts := middlewareCounts(t, routerFor(t))

	lengths := make(map[int][]string)
	for route, n := range counts {
		if strings.HasPrefix(route[strings.Index(route, " ")+1:], "/v1/") {
			lengths[n] = append(lengths[n], route)
		}
	}

	if len(lengths) > 1 {
		for n, routes := range lengths {
			t.Errorf("%d middlewares: %v", n, routes)
		}
		t.Fatal("public routes do not all share one middleware chain; " +
			"at least one is mounted in the wrong group")
	}
}
