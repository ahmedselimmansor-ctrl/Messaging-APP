package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/pervagans/messaging-app/pkg/auditlog"
	"github.com/pervagans/messaging-app/pkg/authn"
	"github.com/pervagans/messaging-app/pkg/events"
	"github.com/pervagans/messaging-app/pkg/httpx"
	"github.com/pervagans/messaging-app/pkg/ids"
	"github.com/pervagans/messaging-app/pkg/kafkax"
	"github.com/pervagans/messaging-app/pkg/pgstore"
	"github.com/pervagans/messaging-app/pkg/ratelimit"
	"github.com/pervagans/messaging-app/pkg/redisx"
	"golang.org/x/crypto/bcrypt"
)

// Service holds the auth service's dependencies.
type Service struct {
	Cfg      Config
	Log      *slog.Logger
	Users    *pgstore.Users
	Devices  *pgstore.Devices
	OTP      *pgstore.OTP
	Contacts *pgstore.Contacts
	Blocks   *pgstore.Blocks
	Issuer   *authn.Issuer
	Verifier *authn.Verifier
	IDs      *ids.Snowflake
	Sender   CodeSender
	Producer *kafkax.Producer
	Redis    *redisx.Client
	Limiter  *ratelimit.Limiter
	Audit    *auditlog.Logger
}

// Routes builds the HTTP surface.
func (s *Service) Routes() http.Handler {
	r := chi.NewRouter()
	for _, mw := range httpx.BaseMiddleware("auth-service") {
		r.Use(mw)
	}

	// Public: no credential required.
	r.Route("/v1/auth", func(r chi.Router) {
		r.Post("/send-code", httpx.H(s.handleSendCode))
		r.Post("/sign-in", httpx.H(s.handleSignIn))
		r.Post("/refresh", httpx.H(s.handleRefresh))
	})

	// The JWKS every other service polls to verify access tokens. Publishing
	// it means a signing-key rotation is a config change in one service, not
	// a synchronised redeploy of the fleet.
	r.Get("/.well-known/jwks.json", httpx.H(s.handleJWKS))

	// Authenticated.
	r.Group(func(r chi.Router) {
		r.Use(authn.Middleware(s.Verifier))
		r.Get("/v1/me", httpx.H(s.handleMe))
		r.Patch("/v1/me", httpx.H(s.handleUpdateProfile))
		r.Delete("/v1/me", httpx.H(s.handleDeleteAccount))
		r.Get("/v1/me/devices", httpx.H(s.handleListDevices))
		r.Delete("/v1/me/devices/{deviceID}", httpx.H(s.handleRevokeDevice))
		r.Post("/v1/me/devices/revoke-others", httpx.H(s.handleRevokeOthers))
		r.Put("/v1/me/push-token", httpx.H(s.handleSetPushToken))
		r.Put("/v1/me/username", httpx.H(s.handleSetUsername))

		// Contacts and the blocklist are properties of an account, and
		// contact import needs the phone column only this service may read.
		r.Post("/v1/contacts/import", httpx.H(s.handleImportContacts))
		r.Get("/v1/contacts", httpx.H(s.handleListContacts))
		r.Post("/v1/contacts", httpx.H(s.handleAddContact))
		r.Delete("/v1/contacts/{userID}", httpx.H(s.handleDeleteContact))

		r.Get("/v1/blocks", httpx.H(s.handleListBlocks))
		r.Post("/v1/blocks", httpx.H(s.handleBlock))
		r.Delete("/v1/blocks/{userID}", httpx.H(s.handleUnblock))
	})

	// Internal: called by the realtime gateway to resolve an access token to
	// a session. Reachable only inside the mesh; the Istio AuthorizationPolicy
	// in deploy/k8s/mesh restricts the caller to the gateway's identity.
	r.Post("/internal/v1/resolve-token", httpx.H(s.handleResolveToken))
	// The send path calls these, so they must be fast and are cached by the
	// caller.
	r.Get("/internal/v1/blocks/check", httpx.H(s.handleBlockCheck))
	r.Post("/internal/v1/blocks/among", httpx.H(s.handleBlockedAmong))
	r.Get("/internal/v1/contacts/{userID}/mutual", httpx.H(s.handleMutualContacts))

	return r
}

// ---------------------------------------------------------------------------
// Phone verification
// ---------------------------------------------------------------------------

// e164 is a deliberately strict phone format: a leading +, a non-zero country
// digit, then 7..14 more digits. Normalising to one canonical form is what
// makes "phone" a safe unique key — "+201234567890", "00201234567890" and
// "01234567890" must not become three accounts.
var e164 = regexp.MustCompile(`^\+[1-9]\d{7,14}$`)

type sendCodeRequest struct {
	Phone string `json:"phone"`
}

type sendCodeResponse struct {
	ChallengeID string `json:"challenge_id"`
	// CodeLength lets the client render the right number of input boxes.
	CodeLength int `json:"code_length"`
	ExpiresIn  int `json:"expires_in"`
	// Registered tells the client whether to ask for a display name after
	// verification. It is not sensitive: an attacker can learn the same thing
	// by attempting a sign-in.
	Registered bool `json:"registered"`
}

func (s *Service) handleSendCode(w http.ResponseWriter, r *http.Request) error {
	var req sendCodeRequest
	if err := httpx.DecodeJSON(r, 4<<10, &req); err != nil {
		return err
	}

	phone := normalisePhone(req.Phone)
	if !e164.MatchString(phone) {
		return httpx.ErrBadRequest("phone must be in E.164 format, e.g. +201234567890")
	}

	ip := httpx.ClientIP(r)
	if err := s.checkLimit(r.Context(), ratelimit.KeyIP("otp_send", ip), ratelimit.OTPRequestPerIP); err != nil {
		return err
	}
	if err := s.checkLimit(r.Context(), ratelimit.KeyPhone("otp_send", phone), ratelimit.OTPRequestPerPhone); err != nil {
		return err
	}

	code, err := s.codeFor(phone)
	if err != nil {
		return httpx.ErrInternal("could not generate a verification code").WithCause(err)
	}

	// bcrypt at the default cost: a verification code lives for five minutes
	// and the table is small, so the ~60ms hash is affordable and it means a
	// database leak does not expose live codes.
	hash, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
	if err != nil {
		return httpx.ErrInternal("could not hash the verification code").WithCause(err)
	}

	challengeID := ids.NewUUID()
	if _, err := s.OTP.Create(r.Context(), challengeID, phone, string(hash), s.Cfg.CodeTTL); err != nil {
		return httpx.ErrInternal("could not create the verification challenge").WithCause(err)
	}

	if !s.isTestPhone(phone) {
		if err := s.Sender.Send(r.Context(), phone, code, s.Cfg.CodeTTL); err != nil {
			// The challenge row already exists; leaving it is harmless since
			// it expires, and failing the request tells the client to retry.
			return httpx.ErrUnavailable("could not deliver the verification code").WithCause(err)
		}
	}

	registered := true
	if _, err := s.Users.GetByPhone(r.Context(), phone); errors.Is(err, pgstore.ErrNotFound) {
		registered = false
	} else if err != nil {
		return httpx.ErrInternal("account lookup failed").WithCause(err)
	}

	httpx.WriteJSON(w, http.StatusOK, sendCodeResponse{
		ChallengeID: challengeID,
		CodeLength:  s.Cfg.CodeLength,
		ExpiresIn:   int(s.Cfg.CodeTTL.Seconds()),
		Registered:  registered,
	})
	return nil
}

type signInRequest struct {
	ChallengeID string `json:"challenge_id"`
	Code        string `json:"code"`
	// DisplayName is required only when the account does not exist yet.
	DisplayName string `json:"display_name,omitempty"`
	Platform    string `json:"platform"`
	AppVersion  string `json:"app_version"`
	DeviceModel string `json:"device_model"`
	LangCode    string `json:"lang_code,omitempty"`
	// AuthKeyID binds this session to an already-negotiated MTProto auth key.
	// Optional: a web client that only uses REST has none.
	AuthKeyID string `json:"auth_key_id,omitempty"`
}

type signInResponse struct {
	AccessToken  string       `json:"access_token"`
	RefreshToken string       `json:"refresh_token"`
	ExpiresIn    int          `json:"expires_in"`
	TokenType    string       `json:"token_type"`
	User         pgstore.User `json:"user"`
	DeviceID     int64        `json:"device_id"`
	Created      bool         `json:"created"`
}

func (s *Service) handleSignIn(w http.ResponseWriter, r *http.Request) error {
	var req signInRequest
	if err := httpx.DecodeJSON(r, 8<<10, &req); err != nil {
		return err
	}
	if req.ChallengeID == "" || req.Code == "" {
		return httpx.ErrBadRequest("challenge_id and code are required")
	}

	ip := httpx.ClientIP(r)
	if err := s.checkLimit(r.Context(), ratelimit.KeyIP("login", ip), ratelimit.LoginPerIP); err != nil {
		return err
	}

	challenge, err := s.OTP.Get(r.Context(), req.ChallengeID)
	if err != nil {
		if errors.Is(err, pgstore.ErrNotFound) {
			// Same message for "no such challenge" and "wrong code": telling
			// them apart would let an attacker enumerate live challenges.
			return httpx.ErrUnauthorized("the verification code is not valid")
		}
		return httpx.ErrInternal("challenge lookup failed").WithCause(err)
	}

	if err := s.checkLimit(r.Context(),
		ratelimit.KeyPhone("otp_verify", challenge.Phone), ratelimit.OTPVerifyPerPhone); err != nil {
		return err
	}

	switch {
	case challenge.ConsumedAt != nil:
		return httpx.ErrUnauthorized("this verification code has already been used")
	case time.Now().After(challenge.ExpiresAt):
		return httpx.ErrUnauthorized("the verification code has expired")
	case challenge.Attempts >= s.Cfg.MaxCodeAttempts:
		return httpx.ErrUnauthorized("too many incorrect attempts; request a new code")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(challenge.CodeHash), []byte(strings.TrimSpace(req.Code))); err != nil {
		n, incErr := s.OTP.IncrementAttempts(r.Context(), challenge.ID)
		if incErr != nil {
			s.Log.Error("could not record a failed attempt", "error", incErr)
		}
		s.Log.Info("verification failed", "challenge", challenge.ID, "attempts", n)
		return httpx.ErrUnauthorized("the verification code is not valid")
	}

	// Consume before issuing anything. The update is conditional on the row
	// still being unconsumed, so two concurrent requests with the same valid
	// code cannot both mint a session.
	if err := s.OTP.Consume(r.Context(), challenge.ID); err != nil {
		if errors.Is(err, pgstore.ErrNotFound) {
			return httpx.ErrUnauthorized("this verification code has already been used")
		}
		return httpx.ErrInternal("could not consume the challenge").WithCause(err)
	}

	user, created, err := s.findOrCreateUser(r.Context(), challenge.Phone, req.DisplayName, req.LangCode)
	if err != nil {
		return err
	}
	if user.Banned {
		return httpx.ErrForbidden("this account has been suspended")
	}

	device, err := s.Devices.Upsert(r.Context(), pgstore.Device{
		ID:          s.IDs.Next(),
		UserID:      user.ID,
		AuthKeyID:   orGenerated(req.AuthKeyID),
		Platform:    orDefault(req.Platform, "unknown"),
		AppVersion:  req.AppVersion,
		DeviceModel: req.DeviceModel,
		LastIP:      ip,
	})
	if err != nil {
		return httpx.ErrInternal("could not register the device").WithCause(err)
	}

	access, refresh, expiresIn, err := s.Issuer.Issue(user.ID, device.ID, nil)
	if err != nil {
		return httpx.ErrInternal("could not issue tokens").WithCause(err)
	}

	// Clear the login backoff for this address now that it has succeeded.
	if err := s.Limiter.Reset(r.Context(), ratelimit.KeyIP("login", ip)); err != nil {
		s.Log.Warn("could not reset the login limiter", "error", err)
	}

	kind := events.DeviceAdded
	if created {
		kind = events.UserCreated
	}
	s.publishUserEvent(r.Context(), events.UserEvent{
		V: events.CurrentVersion, Kind: kind,
		UserID: user.ID, DeviceID: device.ID, At: time.Now().UTC(),
	})

	httpx.WriteJSON(w, http.StatusOK, signInResponse{
		AccessToken:  access,
		RefreshToken: refresh,
		ExpiresIn:    expiresIn,
		TokenType:    "Bearer",
		User:         user,
		DeviceID:     device.ID,
		Created:      created,
	})
	return nil
}

func (s *Service) findOrCreateUser(ctx context.Context, phone, displayName, langCode string) (pgstore.User, bool, error) {
	user, err := s.Users.GetByPhone(ctx, phone)
	if err == nil {
		return user, false, nil
	}
	if !errors.Is(err, pgstore.ErrNotFound) {
		return pgstore.User{}, false, httpx.ErrInternal("account lookup failed").WithCause(err)
	}

	name := strings.TrimSpace(displayName)
	if name == "" {
		return pgstore.User{}, false, httpx.ErrBadRequest("display_name is required to create an account")
	}
	if len([]rune(name)) > 64 {
		return pgstore.User{}, false, httpx.ErrBadRequest("display_name must be at most 64 characters")
	}

	user, err = s.Users.Create(ctx, pgstore.User{
		ID: s.IDs.Next(), Phone: phone, DisplayName: name, LangCode: orDefault(langCode, "en"),
	})
	if err != nil {
		// Another request created the account between our lookup and insert.
		if errors.Is(err, pgstore.ErrConflict) {
			user, err = s.Users.GetByPhone(ctx, phone)
			if err != nil {
				return pgstore.User{}, false, httpx.ErrInternal("account lookup failed").WithCause(err)
			}
			return user, false, nil
		}
		return pgstore.User{}, false, httpx.ErrInternal("could not create the account").WithCause(err)
	}
	return user, true, nil
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func (s *Service) handleRefresh(w http.ResponseWriter, r *http.Request) error {
	var req refreshRequest
	if err := httpx.DecodeJSON(r, 8<<10, &req); err != nil {
		return err
	}

	claims, err := s.Verifier.Verify(req.RefreshToken, authn.RefreshToken)
	if err != nil {
		return httpx.ErrUnauthorized("the refresh token is not valid")
	}

	// A refresh token outlives its device by design (60 days), so the device
	// must be re-checked on every use: this is what makes "log out this
	// session" take effect immediately rather than in two months.
	devices, err := s.Devices.ListForUser(r.Context(), claims.UserID)
	if err != nil {
		return httpx.ErrInternal("device lookup failed").WithCause(err)
	}
	active := false
	for _, d := range devices {
		if d.ID == claims.DeviceID {
			active = true
			break
		}
	}
	if !active {
		return httpx.ErrUnauthorized("this session has been revoked")
	}

	user, err := s.Users.GetByID(r.Context(), claims.UserID)
	if err != nil {
		return httpx.ErrUnauthorized("account not found")
	}
	if user.Banned {
		return httpx.ErrForbidden("this account has been suspended")
	}

	access, refresh, expiresIn, err := s.Issuer.Issue(claims.UserID, claims.DeviceID, claims.Scopes)
	if err != nil {
		return httpx.ErrInternal("could not issue tokens").WithCause(err)
	}

	httpx.WriteJSON(w, http.StatusOK, signInResponse{
		AccessToken:  access,
		RefreshToken: refresh,
		ExpiresIn:    expiresIn,
		TokenType:    "Bearer",
		User:         user,
		DeviceID:     claims.DeviceID,
	})
	return nil
}

func (s *Service) handleJWKS(w http.ResponseWriter, _ *http.Request) error {
	doc, err := s.Issuer.PublicJWKS()
	if err != nil {
		return httpx.ErrInternal("could not render the key set").WithCause(err)
	}
	// Cache for an hour: long enough to keep the endpoint cold, short enough
	// that a rotation propagates without a deploy.
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(doc)
	return nil
}

// ---------------------------------------------------------------------------
// Account and session management
// ---------------------------------------------------------------------------

func (s *Service) handleMe(w http.ResponseWriter, r *http.Request) error {
	userID, err := authn.MustUserID(r.Context())
	if err != nil {
		return err
	}
	user, err := s.Users.GetByID(r.Context(), userID)
	if err != nil {
		return httpx.ErrNotFound("account not found")
	}
	httpx.WriteJSON(w, http.StatusOK, user)
	return nil
}

type updateProfileRequest struct {
	DisplayName *string `json:"display_name,omitempty"`
	About       *string `json:"about,omitempty"`
	AvatarObj   *string `json:"avatar_object,omitempty"`
	LangCode    *string `json:"lang_code,omitempty"`
}

func (s *Service) handleUpdateProfile(w http.ResponseWriter, r *http.Request) error {
	userID, err := authn.MustUserID(r.Context())
	if err != nil {
		return err
	}
	var req updateProfileRequest
	if err := httpx.DecodeJSON(r, 8<<10, &req); err != nil {
		return err
	}
	if req.DisplayName != nil {
		name := strings.TrimSpace(*req.DisplayName)
		if name == "" || len([]rune(name)) > 64 {
			return httpx.ErrBadRequest("display_name must be 1..64 characters")
		}
		req.DisplayName = &name
	}
	if req.About != nil && len([]rune(*req.About)) > 280 {
		return httpx.ErrBadRequest("about must be at most 280 characters")
	}

	user, err := s.Users.UpdateProfile(r.Context(), userID,
		req.DisplayName, req.About, req.AvatarObj, req.LangCode)
	if err != nil {
		return httpx.ErrInternal("could not update the profile").WithCause(err)
	}

	s.publishUserEvent(r.Context(), events.UserEvent{
		V: events.CurrentVersion, Kind: events.UserUpdated, UserID: userID, At: time.Now().UTC(),
	})
	httpx.WriteJSON(w, http.StatusOK, user)
	return nil
}

type setUsernameRequest struct {
	Username string `json:"username"`
}

var usernameRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{4,31}$`)

func (s *Service) handleSetUsername(w http.ResponseWriter, r *http.Request) error {
	userID, err := authn.MustUserID(r.Context())
	if err != nil {
		return err
	}
	var req setUsernameRequest
	if err := httpx.DecodeJSON(r, 1<<10, &req); err != nil {
		return err
	}
	username := strings.TrimSpace(req.Username)
	if username != "" && !usernameRe.MatchString(username) {
		return httpx.ErrBadRequest(
			"username must start with a letter and be 5..32 characters of letters, digits or underscores")
	}

	if err := s.Users.SetUsername(r.Context(), userID, username); err != nil {
		if errors.Is(err, pgstore.ErrConflict) {
			return httpx.ErrConflict("that username is already taken")
		}
		return httpx.ErrInternal("could not set the username").WithCause(err)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"username": username})
	return nil
}

func (s *Service) handleDeleteAccount(w http.ResponseWriter, r *http.Request) error {
	claims, ok := authn.ClaimsFrom(r.Context())
	if !ok {
		return httpx.ErrUnauthorized("authorization required")
	}

	if _, err := s.Devices.RevokeAllExcept(r.Context(), claims.UserID, 0); err != nil {
		return httpx.ErrInternal("could not revoke sessions").WithCause(err)
	}
	if err := s.Users.SoftDelete(r.Context(), claims.UserID); err != nil {
		return httpx.ErrInternal("could not delete the account").WithCause(err)
	}

	s.publishUserEvent(r.Context(), events.UserEvent{
		V: events.CurrentVersion, Kind: events.UserDeleted,
		UserID: claims.UserID, At: time.Now().UTC(),
	})
	s.audit(r.Context(), r, auditlog.Entry{
		Action:     auditlog.ActionAccountDeleted,
		ActorID:    claims.UserID,
		ActorType:  "user",
		TargetType: "user",
		TargetID:   claims.UserID,
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]bool{"deleted": true})
	return nil
}

func (s *Service) handleListDevices(w http.ResponseWriter, r *http.Request) error {
	userID, err := authn.MustUserID(r.Context())
	if err != nil {
		return err
	}
	devices, err := s.Devices.ListForUser(r.Context(), userID)
	if err != nil {
		return httpx.ErrInternal("device lookup failed").WithCause(err)
	}
	// Never return push tokens: they are credentials for sending to a device.
	for i := range devices {
		devices[i].PushToken = nil
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"devices": devices})
	return nil
}

func (s *Service) handleRevokeDevice(w http.ResponseWriter, r *http.Request) error {
	claims, ok := authn.ClaimsFrom(r.Context())
	if !ok {
		return httpx.ErrUnauthorized("authorization required")
	}
	deviceID, err := httpx.PathInt64(r, "deviceID")
	if err != nil {
		return err
	}

	if err := s.Devices.Revoke(r.Context(), claims.UserID, deviceID); err != nil {
		if errors.Is(err, pgstore.ErrNotFound) {
			return httpx.ErrNotFound("no such active session")
		}
		return httpx.ErrInternal("could not revoke the session").WithCause(err)
	}

	s.publishUserEvent(r.Context(), events.UserEvent{
		V: events.CurrentVersion, Kind: events.DeviceRevoke,
		UserID: claims.UserID, DeviceID: deviceID, At: time.Now().UTC(),
	})
	s.audit(r.Context(), r, auditlog.Entry{
		Action:     auditlog.ActionDeviceRevoked,
		ActorID:    claims.UserID,
		ActorType:  "user",
		TargetType: "device",
		TargetID:   deviceID,
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]bool{"revoked": true})
	return nil
}

func (s *Service) handleRevokeOthers(w http.ResponseWriter, r *http.Request) error {
	claims, ok := authn.ClaimsFrom(r.Context())
	if !ok {
		return httpx.ErrUnauthorized("authorization required")
	}
	n, err := s.Devices.RevokeAllExcept(r.Context(), claims.UserID, claims.DeviceID)
	if err != nil {
		return httpx.ErrInternal("could not revoke sessions").WithCause(err)
	}
	// Recorded even when it revokes nothing. "I signed out everywhere" is a
	// claim people make after a suspected compromise, and the useful record is
	// that they tried and when — not only the cases where sessions existed.
	s.audit(r.Context(), r, auditlog.Entry{
		Action:     auditlog.ActionDeviceRevoked,
		ActorID:    claims.UserID,
		ActorType:  "user",
		TargetType: "user",
		TargetID:   claims.UserID,
		Detail: map[string]string{
			"scope": "all_other_sessions",
			"count": strconv.FormatInt(n, 10),
		},
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]int64{"revoked": n})
	return nil
}

type setPushTokenRequest struct {
	PushToken string `json:"push_token"`
}

func (s *Service) handleSetPushToken(w http.ResponseWriter, r *http.Request) error {
	claims, ok := authn.ClaimsFrom(r.Context())
	if !ok {
		return httpx.ErrUnauthorized("authorization required")
	}
	var req setPushTokenRequest
	if err := httpx.DecodeJSON(r, 4<<10, &req); err != nil {
		return err
	}
	if len(req.PushToken) > 4096 {
		return httpx.ErrBadRequest("push_token is too long")
	}
	if err := s.Devices.SetPushToken(r.Context(), claims.DeviceID, req.PushToken); err != nil {
		return httpx.ErrInternal("could not store the push token").WithCause(err)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
	return nil
}

// ---------------------------------------------------------------------------
// Internal
// ---------------------------------------------------------------------------

type resolveTokenRequest struct {
	AccessToken string `json:"access_token"`
	AuthKeyID   string `json:"auth_key_id,omitempty"`
	Platform    string `json:"platform,omitempty"`
	AppVersion  string `json:"app_version,omitempty"`
	DeviceModel string `json:"device_model,omitempty"`
	IP          string `json:"ip,omitempty"`
}

type resolveTokenResponse struct {
	UserID      int64  `json:"user_id"`
	DeviceID    int64  `json:"device_id"`
	DisplayName string `json:"display_name"`
	LangCode    string `json:"lang_code"`
}

// handleResolveToken lets the realtime gateway turn an access token plus a
// negotiated auth key into a durable device record, in one call.
//
// The gateway could verify the JWT itself — it holds the JWKS — but the device
// row must be created or refreshed by the service that owns that table, and
// doing it here keeps the write path in one place.
func (s *Service) handleResolveToken(w http.ResponseWriter, r *http.Request) error {
	var req resolveTokenRequest
	if err := httpx.DecodeJSON(r, 16<<10, &req); err != nil {
		return err
	}

	claims, err := s.Verifier.Verify(req.AccessToken, authn.AccessToken)
	if err != nil {
		if errors.Is(err, authn.ErrExpired) {
			return httpx.ErrUnauthorized("access token expired")
		}
		return httpx.ErrUnauthorized("invalid access token")
	}

	user, err := s.Users.GetByID(r.Context(), claims.UserID)
	if err != nil {
		return httpx.ErrUnauthorized("account not found")
	}
	if user.Banned {
		return httpx.ErrForbidden("this account has been suspended")
	}

	deviceID := claims.DeviceID
	if req.AuthKeyID != "" {
		device, err := s.Devices.Upsert(r.Context(), pgstore.Device{
			ID:          s.IDs.Next(),
			UserID:      user.ID,
			AuthKeyID:   req.AuthKeyID,
			Platform:    orDefault(req.Platform, "unknown"),
			AppVersion:  req.AppVersion,
			DeviceModel: req.DeviceModel,
			LastIP:      req.IP,
		})
		if err != nil {
			return httpx.ErrInternal("could not register the device").WithCause(err)
		}
		deviceID = device.ID
	}

	httpx.WriteJSON(w, http.StatusOK, resolveTokenResponse{
		UserID:      user.ID,
		DeviceID:    deviceID,
		DisplayName: user.DisplayName,
		LangCode:    user.LangCode,
	})
	return nil
}

// PublishServiceEvent emits a lifecycle event on user.events.
func (s *Service) PublishServiceEvent(ctx context.Context, e events.UserEvent) error {
	body, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return s.Producer.Publish(ctx, events.TopicUserEvents, nil, body)
}

func (s *Service) publishUserEvent(ctx context.Context, e events.UserEvent) {
	body, err := json.Marshal(e)
	if err != nil {
		s.Log.Error("could not marshal a user event", "error", err)
		return
	}
	key := []byte(fmt.Sprint(e.UserID))
	// Publishing must not fail the user's request: the account change is
	// already committed, and the event is for downstream consumers only.
	if err := s.Producer.Publish(ctx, events.TopicUserEvents, key, body); err != nil {
		s.Log.Error("could not publish a user event", "kind", e.Kind, "error", err)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func (s *Service) checkLimit(ctx context.Context, key string, lim ratelimit.Limit) error {
	d, err := s.Limiter.Allow(ctx, key, lim)
	if err != nil {
		s.Log.Error("rate limiter unavailable, failing closed", "key", key, "error", err)
		return httpx.ErrUnavailable("service temporarily unavailable")
	}
	if !d.Allowed {
		seconds := int(d.RetryAfter.Seconds()) + 1
		return httpx.ErrFloodWait(seconds)
	}
	return nil
}

// codeFor returns the verification code, honouring the test-phone override.
func (s *Service) codeFor(phone string) (string, error) {
	if s.isTestPhone(phone) {
		return s.Cfg.TestPhoneCode, nil
	}
	return ids.NumericCode(s.Cfg.CodeLength)
}

func (s *Service) isTestPhone(phone string) bool {
	return s.Cfg.TestPhonePrefix != "" &&
		s.Cfg.TestPhoneCode != "" &&
		strings.HasPrefix(phone, s.Cfg.TestPhonePrefix)
}

// normalisePhone converts common input forms into E.164.
func normalisePhone(raw string) string {
	var b strings.Builder
	for i, r := range strings.TrimSpace(raw) {
		switch {
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '+' && i == 0:
			b.WriteRune(r)
		}
	}
	s := b.String()
	// "0020..." is the international prefix written the old way.
	if strings.HasPrefix(s, "00") {
		return "+" + s[2:]
	}
	if !strings.HasPrefix(s, "+") && s != "" {
		return "+" + s
	}
	return s
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

// orGenerated returns the given auth key id, or a synthetic one for REST-only
// sessions that never negotiated an MTProto key.
func orGenerated(authKeyID string) string {
	if authKeyID != "" {
		return authKeyID
	}
	return "rest:" + ids.NewUUID()
}

// handleMutualContacts returns everyone who has this user in their contacts.
//
// Presence visibility keys off it: someone who never saved your number should
// not learn when you come online.
func (s *Service) handleMutualContacts(w http.ResponseWriter, r *http.Request) error {
	userID, err := httpx.PathInt64(r, "userID")
	if err != nil {
		return err
	}
	ids, err := s.Contacts.MutualIDs(r.Context(), userID)
	if err != nil {
		return httpx.ErrInternal("contact lookup failed").WithCause(err)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"user_ids": ids})
	return nil
}
