package httpx

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// ---------------------------------------------------------------------------
// The error envelope
// ---------------------------------------------------------------------------

// The envelope is the platform's public contract: clients switch on `code`.
// It is also the place an internal detail would leak if anything let it
// through, which is what most of these tests are checking.

func decodeEnvelope(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var out struct {
		Error map[string]any `json:"error"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("response is not the error envelope: %v (%s)", err, body)
	}
	if out.Error == nil {
		t.Fatalf("response has no error object: %s", body)
	}
	return out.Error
}

func TestWriteErrorNeverLeaksTheInternalCause(t *testing.T) {
	// The cause carries whatever the failing layer said — a DSN, a query, an
	// internal hostname. It belongs in the log, never in the response.
	secret := "postgres://user:hunter2@10.0.0.5:5432/messaging"
	err := ErrInternal("internal error").WithCause(errors.New(secret))

	w := httptest.NewRecorder()
	WriteError(w, httptest.NewRequest(http.MethodGet, "/v1/me", nil), err)

	if strings.Contains(w.Body.String(), "hunter2") || strings.Contains(w.Body.String(), "10.0.0.5") {
		t.Fatalf("the internal cause leaked into the response: %s", w.Body.String())
	}
	env := decodeEnvelope(t, w.Body.Bytes())
	if env["code"] != string(CodeInternal) {
		t.Errorf("code = %v, want %v", env["code"], CodeInternal)
	}
}

func TestWriteErrorMapsAnUnknownErrorToA500(t *testing.T) {
	// A handler returning a bare error must not produce a 200 with an empty
	// body, and must not echo the message.
	w := httptest.NewRecorder()
	WriteError(w, httptest.NewRequest(http.MethodGet, "/", nil),
		errors.New("some internal detail about table layouts"))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
	if strings.Contains(w.Body.String(), "table layouts") {
		t.Errorf("a bare error's message reached the client: %s", w.Body.String())
	}
}

func TestErrorStatusesMatchTheirConstructors(t *testing.T) {
	cases := []struct {
		err  *APIError
		want int
	}{
		{ErrBadRequest("x"), http.StatusBadRequest},
		{ErrUnauthorized("x"), http.StatusUnauthorized},
		{ErrForbidden("x"), http.StatusForbidden},
		{ErrNotFound("x"), http.StatusNotFound},
		{ErrConflict("x"), http.StatusConflict},
		{ErrInternal("x"), http.StatusInternalServerError},
		{ErrUnavailable("x"), http.StatusServiceUnavailable},
	}
	for _, tc := range cases {
		w := httptest.NewRecorder()
		WriteError(w, httptest.NewRequest(http.MethodGet, "/", nil), tc.err)
		if w.Code != tc.want {
			t.Errorf("%s: status = %d, want %d", tc.err.Code, w.Code, tc.want)
		}
		if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			t.Errorf("%s: Content-Type = %q, want JSON", tc.err.Code, ct)
		}
	}
}

func TestFloodWaitCarriesRetryAfter(t *testing.T) {
	// A client that cannot see how long to wait will retry immediately and
	// make the overload worse. The header is what makes backoff possible for
	// clients that do not parse the body.
	w := httptest.NewRecorder()
	WriteError(w, httptest.NewRequest(http.MethodGet, "/", nil), ErrFloodWait(30))

	if got := w.Header().Get("Retry-After"); got != "30" {
		t.Errorf("Retry-After = %q, want 30", got)
	}
	env := decodeEnvelope(t, w.Body.Bytes())
	if env["retry_after"] != float64(30) {
		t.Errorf("retry_after = %v, want 30", env["retry_after"])
	}
}

func TestErrorUnwrapsToItsCause(t *testing.T) {
	// errors.Is through an APIError is what lets a caller distinguish a
	// not-found from a transport failure without string matching.
	sentinel := errors.New("sentinel")
	err := ErrInternal("wrapped").WithCause(sentinel)
	if !errors.Is(err, sentinel) {
		t.Error("errors.Is could not reach the cause through an APIError")
	}
}

func TestHandlerAdapterWritesTheEnvelope(t *testing.T) {
	h := H(func(w http.ResponseWriter, r *http.Request) error {
		return ErrForbidden("you cannot do that")
	})
	w := httptest.NewRecorder()
	h(w, httptest.NewRequest(http.MethodGet, "/", nil))

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
	env := decodeEnvelope(t, w.Body.Bytes())
	if env["message"] != "you cannot do that" {
		t.Errorf("message = %v", env["message"])
	}
}

func TestHandlerAdapterWritesNothingOnSuccess(t *testing.T) {
	// A handler that already wrote its response must not have an envelope
	// appended after it.
	h := H(func(w http.ResponseWriter, r *http.Request) error {
		WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
		return nil
	})
	w := httptest.NewRecorder()
	h(w, httptest.NewRequest(http.MethodGet, "/", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if strings.Contains(w.Body.String(), "error") {
		t.Errorf("an error envelope was appended to a successful response: %s", w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Body decoding
// ---------------------------------------------------------------------------

type testPayload struct {
	Name string `json:"name"`
	N    int    `json:"n"`
}

func postJSON(body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	return r
}

func TestDecodeJSONAcceptsAWellFormedBody(t *testing.T) {
	var p testPayload
	if err := DecodeJSON(postJSON(`{"name":"a","n":1}`), 1024, &p); err != nil {
		t.Fatal(err)
	}
	if p.Name != "a" || p.N != 1 {
		t.Errorf("decoded %+v", p)
	}
}

func TestDecodeJSONEnforcesTheSizeLimit(t *testing.T) {
	// Without the cap, a client can make the server allocate as much as it
	// likes — a trivial denial of service against every endpoint at once.
	big := `{"name":"` + strings.Repeat("A", 10_000) + `"}`

	var p testPayload
	err := DecodeJSON(postJSON(big), 128, &p)
	if err == nil {
		t.Fatal("DecodeJSON accepted a body far over the limit")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status() != http.StatusRequestEntityTooLarge {
		t.Errorf("err = %v, want a 413", err)
	}
}

func TestDecodeJSONRejectsUnknownFields(t *testing.T) {
	// A typo in a client payload should be a loud 400, not a silently ignored
	// field that makes a feature appear not to work.
	var p testPayload
	err := DecodeJSON(postJSON(`{"name":"a","nmae":2}`), 1024, &p)
	if err == nil {
		t.Fatal("DecodeJSON accepted an unknown field")
	}
}

func TestDecodeJSONRejectsTrailingContent(t *testing.T) {
	// Two objects in one body is a request smuggling shape: which one takes
	// effect would depend on the decoder, so neither does.
	var p testPayload
	if err := DecodeJSON(postJSON(`{"name":"a"}{"name":"b"}`), 1024, &p); err == nil {
		t.Fatal("DecodeJSON accepted two JSON objects in one body")
	}
}

func TestDecodeJSONRejectsAWrongContentType(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"a"}`))
	r.Header.Set("Content-Type", "text/plain")

	var p testPayload
	if err := DecodeJSON(r, 1024, &p); err == nil {
		t.Fatal("DecodeJSON accepted text/plain")
	}
}

func TestDecodeJSONAcceptsAContentTypeWithParameters(t *testing.T) {
	// Browsers send "application/json; charset=utf-8". Rejecting that would
	// break every web client.
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"a"}`))
	r.Header.Set("Content-Type", "application/json; charset=utf-8")

	var p testPayload
	if err := DecodeJSON(r, 1024, &p); err != nil {
		t.Fatalf("a charset parameter was rejected: %v", err)
	}
}

func TestDecodeJSONRejectsMalformedAndEmptyBodies(t *testing.T) {
	for _, body := range []string{"", "{", "not json", "[]", "null"} {
		var p testPayload
		if err := DecodeJSON(postJSON(body), 1024, &p); err == nil && body != "null" {
			t.Errorf("DecodeJSON(%q) succeeded, want an error", body)
		}
	}
}

// ---------------------------------------------------------------------------
// Parameters
// ---------------------------------------------------------------------------

func withURLParam(name, value string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(name, value)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

func TestPathInt64RejectsNonIntegers(t *testing.T) {
	// These reach handlers that use the value as an identifier. A silent zero
	// would become "chat 0", which is a real lookup against a phantom row.
	for _, raw := range []string{"", "abc", "1.5", "0x10", " 1", "9223372036854775808"} {
		if _, err := PathInt64(withURLParam("chatID", raw), "chatID"); err == nil {
			t.Errorf("PathInt64(%q) succeeded, want an error", raw)
		}
	}

	got, err := PathInt64(withURLParam("chatID", "-42"), "chatID")
	if err != nil || got != -42 {
		t.Errorf("PathInt64(-42) = %d, %v", got, err)
	}
}

func TestQueryIntClampsRatherThanFailing(t *testing.T) {
	// Clamping is right for pagination: a client asking for a million rows
	// should get the maximum page, not an error it has to handle.
	cases := []struct {
		raw  string
		want int
	}{
		{"", 50},         // absent → default
		{"garbage", 50},  // unparseable → default
		{"10", 10},       // in range
		{"0", 1},         // below min → min
		{"-5", 1},        // negative → min
		{"1000000", 200}, // above max → max
	}
	for _, tc := range cases {
		r := httptest.NewRequest(http.MethodGet, "/?limit="+tc.raw, nil)
		if got := QueryInt(r, "limit", 50, 1, 200); got != tc.want {
			t.Errorf("QueryInt(%q) = %d, want %d", tc.raw, got, tc.want)
		}
	}
}

func TestQueryInt64FallsBackToTheDefault(t *testing.T) {
	for _, raw := range []string{"", "abc", "1.5"} {
		r := httptest.NewRequest(http.MethodGet, "/?before="+raw, nil)
		if got := QueryInt64(r, "before", 7); got != 7 {
			t.Errorf("QueryInt64(%q) = %d, want the default 7", raw, got)
		}
	}
	r := httptest.NewRequest(http.MethodGet, "/?before=123", nil)
	if got := QueryInt64(r, "before", 7); got != 123 {
		t.Errorf("QueryInt64(123) = %d", got)
	}
}

// ---------------------------------------------------------------------------
// ClientIP
// ---------------------------------------------------------------------------

func TestClientIPReadsRemoteAddrNotTheHeader(t *testing.T) {
	// This is the security-relevant part. RealIP middleware has already
	// applied the load balancer's rule by the time a handler runs, so
	// RemoteAddr is authoritative. Reading X-Forwarded-For again here would
	// let any client forge the address that rate limits and audit entries are
	// keyed on.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.7:54321"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")

	if got := ClientIP(r); got != "203.0.113.7" {
		t.Errorf("ClientIP = %q, want the RemoteAddr host — a forged header must not win", got)
	}
}

func TestClientIPHandlesAddressesWithoutAPort(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.7"
	if got := ClientIP(r); got != "203.0.113.7" {
		t.Errorf("ClientIP = %q, want 203.0.113.7", got)
	}
}

func TestClientIPHandlesIPv6(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "[2001:db8::1]:443"
	if got := ClientIP(r); got != "2001:db8::1" {
		t.Errorf("ClientIP = %q, want 2001:db8::1", got)
	}
}

// ---------------------------------------------------------------------------
// Recoverer
// ---------------------------------------------------------------------------

func TestRecovererTurnsAPanicIntoA500(t *testing.T) {
	// A panic in one handler must not take the process down with every other
	// in-flight request on it.
	h := Recoverer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("something went very wrong with secret-looking detail")
	}))

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
	if strings.Contains(w.Body.String(), "secret-looking detail") {
		t.Errorf("the panic value reached the client: %s", w.Body.String())
	}
}
