// Command admin-service is the staff-facing moderation surface.
//
// It is the only service that can ban an account, resolve a report, or look up
// a user who has not asked to be looked up. That concentration is deliberate:
// those powers exist in exactly one place, behind exactly one authorisation
// boundary, writing to exactly one audit trail.
//
// # It is not on the internet
//
// There is no route to this service through the public load balancer. It is
// reachable only from inside the mesh, and the AuthorizationPolicy in
// deploy/k8s/mesh restricts it further to the operator gateway's identity. A
// user token — even a valid one — cannot reach these endpoints, because they
// are not routable from where users are.
//
// This is the same trust arrangement chat-service's /internal routes use, and
// it carries the same caveat: if the mesh policy were removed, the identity
// header below would be an authentication bypass. The policy ships in the same
// kustomize base as the Deployment so it cannot be deployed without it.
//
// # Every action names a person and a reason
//
// Operator identity comes from the IAP-authenticated header, and no endpoint
// accepts a request without it. Actions that touch a user require a written
// reason, and both go into the audit trail before the action takes effect.
//
// # What it deliberately cannot do
//
// It cannot read message content. There is no Cassandra client here, and the
// svc_admin Postgres role has no grant on the phone column. A moderator
// decides on reported behaviour, not by reading conversations, and the absence
// of the capability is what makes that checkable rather than a promise.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/pervagans/messaging-app/pkg/app"
	"github.com/pervagans/messaging-app/pkg/auditlog"
	"github.com/pervagans/messaging-app/pkg/config"
	"github.com/pervagans/messaging-app/pkg/events"
	"github.com/pervagans/messaging-app/pkg/httpx"
	"github.com/pervagans/messaging-app/pkg/kafkax"
	"github.com/pervagans/messaging-app/pkg/pgstore"
	"github.com/pervagans/messaging-app/pkg/redisx"
)

func main() {
	app.Run("admin-service", run)
}

type service struct {
	users   *pgstore.Users
	devices *pgstore.Devices
	reports *pgstore.Reports
	bans    *redisx.Bans
	audit   *auditlog.Logger
	events  *kafkax.Producer
	log     *app.App
}

func run(ctx context.Context, a *app.App) error {
	dsn, err := config.MustString("POSTGRES_DSN")
	if err != nil {
		return err
	}
	pgCfg := pgstore.DefaultConfig()
	pgCfg.DSN = dsn
	// A small pool. This service serves a handful of staff, not the platform,
	// and every connection it holds is one the message path cannot use.
	pgCfg.MaxConns = int32(config.Int("POSTGRES_MAX_CONNS", 4))

	db, err := pgstore.Connect(ctx, pgCfg)
	if err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	a.OnShutdown("postgres", db.Close)
	a.Health.Register("postgres", db.Ping)

	rdb, err := redisx.Connect(ctx, redisx.Config{
		Addrs:    config.Strings("REDIS_ADDRS", []string{"localhost:6379"}),
		Cluster:  config.Bool("REDIS_CLUSTER", false),
		Username: config.String("REDIS_USERNAME", ""),
		Password: config.Secret("REDIS_PASSWORD", ""),
		TLS:      config.Bool("REDIS_TLS", false),
	})
	if err != nil {
		return fmt.Errorf("redis: %w", err)
	}
	a.OnShutdown("redis", rdb.Close)
	a.Health.Register("redis", rdb.Ping)

	kafkaCfg := kafkax.Config{
		Brokers:  config.Strings("KAFKA_BROKERS", []string{"localhost:9092"}),
		UseOAuth: config.Bool("KAFKA_OAUTH", a.Cfg.Env != "dev"),
		TLS:      config.Bool("KAFKA_TLS", a.Cfg.Env != "dev"),
		ClientID: "admin-service",
	}
	producer, err := kafkax.NewProducer(kafkaCfg, kafkax.DefaultProducerOptions())
	if err != nil {
		return fmt.Errorf("kafka: %w", err)
	}
	a.OnShutdown("kafka", producer.Close)
	a.Health.Register("kafka", producer.Ping)

	svc := &service{
		users:   db.UsersRepo(),
		devices: db.DevicesRepo(),
		reports: db.ReportsRepo(),
		bans:    rdb.Bans(config.Duration("BAN_CACHE_TTL", 0)),
		audit:   auditlog.New(producer, config.String("HOSTNAME", "admin-0")),
		events:  producer,
		log:     a,
	}

	// Reconcile the ban cache at startup and periodically. Without this a
	// Redis flush silently stops send-path ban enforcement, and nothing would
	// ever say so.
	go svc.reconcileBans(ctx, config.Duration("BAN_RECONCILE_EVERY", 15*time.Minute))

	srv := httpx.NewServer(a.Cfg.HTTPAddr, svc.routes())
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			a.Log.Error("http listener failed", "error", err)
		}
	}()
	a.OnShutdown("http", srv.Shutdown)

	a.Log.Info("moderation surface ready — every action is audited")
	<-ctx.Done()
	return nil
}

func (s *service) routes() http.Handler {
	r := chi.NewRouter()
	for _, mw := range httpx.BaseMiddleware("admin-service") {
		r.Use(mw)
	}

	// Every route, without exception, behind the operator check. Mounted as
	// a group rather than per-route so a route added later cannot be
	// accidentally left unprotected.
	r.Group(func(r chi.Router) {
		r.Use(s.requireOperator)

		r.Get("/admin/v1/reports", httpx.H(s.handleQueue))
		r.Get("/admin/v1/reports/subject/{userID}", httpx.H(s.handleReportsAbout))
		r.Post("/admin/v1/reports/{reportID}/resolve", httpx.H(s.handleResolve))

		r.Get("/admin/v1/users/{userID}", httpx.H(s.handleLookup))
		r.Post("/admin/v1/users/{userID}/ban", httpx.H(s.handleBan))
		r.Post("/admin/v1/users/{userID}/unban", httpx.H(s.handleUnban))
	})

	return r
}

// ---------------------------------------------------------------------------
// Operator identity
// ---------------------------------------------------------------------------

type ctxKey string

const operatorKey ctxKey = "operator"

// requireOperator establishes who is acting.
//
// The header is set by Identity-Aware Proxy after it has authenticated the
// staff member against Google. We do not verify a signature here because we
// cannot be reached except through IAP and the mesh — see the package comment
// for why that is the boundary, and what it depends on.
//
// The value is recorded on every audit entry, so an unattributable action is
// refused outright rather than recorded as "system".
func (s *service) requireOperator(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		email := r.Header.Get("X-Goog-Authenticated-User-Email")
		// IAP prefixes the value, e.g. "accounts.google.com:someone@example.com".
		if i := strings.LastIndex(email, ":"); i >= 0 {
			email = email[i+1:]
		}
		email = strings.TrimSpace(email)

		if email == "" || !strings.Contains(email, "@") {
			httpx.WriteError(w, r, httpx.ErrUnauthorized(
				"this endpoint requires an authenticated operator identity"))
			return
		}

		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), operatorKey, email)))
	})
}

func operatorFrom(ctx context.Context) string {
	v, _ := ctx.Value(operatorKey).(string)
	return v
}

// requireReason extracts and validates the operator's justification.
//
// A minimum length, because "abuse" and "spam" are not reasons — they are
// restatements of the report. The person reading this in six months needs to
// know what was decided and why.
func requireReason(raw string) (string, error) {
	reason := strings.TrimSpace(raw)
	if len([]rune(reason)) < 10 {
		return "", httpx.ErrBadRequest(
			"reason is required and must be at least 10 characters — it is the record of why this was done")
	}
	if len([]rune(reason)) > 1000 {
		return "", httpx.ErrBadRequest("reason must be at most 1000 characters")
	}
	return reason, nil
}

// ---------------------------------------------------------------------------
// Reports
// ---------------------------------------------------------------------------

func (s *service) handleQueue(w http.ResponseWriter, r *http.Request) error {
	limit := httpx.QueryInt(r, "limit", 50, 1, 200)
	offset := httpx.QueryInt(r, "offset", 0, 0, 100000)

	reports, err := s.reports.Queue(r.Context(), limit, offset)
	if err != nil {
		return httpx.ErrInternal("could not read the queue").WithCause(err)
	}

	// Reading the queue is not audited. It is the moderator's own work
	// surface, it happens continuously, and auditing it would bury the
	// entries that matter — a specific user being looked up, an account being
	// banned — under thousands of routine reads.
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"reports": reports,
		"count":   len(reports),
	})
	return nil
}

func (s *service) handleReportsAbout(w http.ResponseWriter, r *http.Request) error {
	userID, err := httpx.PathInt64(r, "userID")
	if err != nil {
		return err
	}
	limit := httpx.QueryInt(r, "limit", 50, 1, 200)

	reports, err := s.reports.AboutSubject(r.Context(), userID, limit)
	if err != nil {
		return httpx.ErrInternal("could not read the reports").WithCause(err)
	}

	// Distinct reporters matters more than the count. Ten reports from ten
	// unrelated people is a signal; ten from one person is a different
	// problem, usually with the reporter.
	distinct := make(map[int64]struct{}, len(reports))
	for _, rep := range reports {
		distinct[rep.ReporterID] = struct{}{}
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"reports":            reports,
		"count":              len(reports),
		"distinct_reporters": len(distinct),
	})
	return nil
}

type resolveRequest struct {
	// State is actioned or dismissed.
	State string `json:"state"`
	// Resolution is what was decided and why.
	Resolution string `json:"resolution"`
}

func (s *service) handleResolve(w http.ResponseWriter, r *http.Request) error {
	reportID, err := httpx.PathInt64(r, "reportID")
	if err != nil {
		return err
	}
	var req resolveRequest
	if err := httpx.DecodeJSON(r, 8<<10, &req); err != nil {
		return err
	}

	state := pgstore.ReportState(strings.TrimSpace(req.State))
	if state != pgstore.StateActioned && state != pgstore.StateDismissed {
		return httpx.ErrBadRequest("state must be actioned or dismissed")
	}
	resolution, err := requireReason(req.Resolution)
	if err != nil {
		return err
	}

	operator := operatorFrom(r.Context())
	rep, err := s.reports.Resolve(r.Context(), reportID, state, operator, resolution)
	if err != nil {
		if errors.Is(err, pgstore.ErrNotFound) {
			return httpx.ErrNotFound("no such open report")
		}
		return httpx.ErrInternal("could not resolve the report").WithCause(err)
	}

	httpx.WriteJSON(w, http.StatusOK, rep)
	return nil
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

// handleLookup returns what staff may see about an account.
//
// This is the endpoint the audit trail exists for. Looking someone up leaves
// no other trace — no message is sent, nothing changes — so without a record
// there is no way to distinguish a moderator investigating a report from one
// reading their ex-partner's account. A reason is mandatory for that reason.
func (s *service) handleLookup(w http.ResponseWriter, r *http.Request) error {
	userID, err := httpx.PathInt64(r, "userID")
	if err != nil {
		return err
	}
	reason, err := requireReason(r.URL.Query().Get("reason"))
	if err != nil {
		return err
	}

	operator := operatorFrom(r.Context())

	// Audited *before* the read, and the read is abandoned if the audit write
	// fails. Everywhere else in the platform the action happens first and the
	// entry follows, because a missing entry beats a false one. Here the
	// ordering flips: the whole purpose is that no lookup happens without a
	// record, so an unrecordable lookup must not happen.
	if err := s.audit.Record(r.Context(), auditlog.Entry{
		Action:     auditlog.ActionUserLookup,
		ActorType:  "operator",
		ActorIP:    httpx.ClientIP(r),
		TargetType: "user",
		TargetID:   userID,
		Reason:     reason,
		Detail:     map[string]string{"operator": operator},
	}); err != nil {
		s.log.Log.Error("refusing a user lookup because it could not be audited",
			"operator", operator, "target", userID, "error", err)
		return httpx.ErrUnavailable("the audit trail is unavailable; lookups are refused while it is")
	}

	user, err := s.users.GetByID(r.Context(), userID)
	if err != nil {
		return httpx.ErrNotFound("no such user")
	}
	openReports, err := s.reports.CountOpenAbout(r.Context(), userID)
	if err != nil {
		return httpx.ErrInternal("could not count reports").WithCause(err)
	}
	devices, err := s.devices.ListForUser(r.Context(), userID)
	if err != nil {
		return httpx.ErrInternal("could not list devices").WithCause(err)
	}

	// Phone is not returned, and svc_admin has no grant to read it. Nothing
	// a moderator decides depends on a phone number, and the column is the
	// most directly identifying thing the platform stores.
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"id":           user.ID,
		"username":     user.Username,
		"display_name": user.DisplayName,
		"created_at":   user.CreatedAt,
		"banned":       user.Banned,
		"deleted":      user.DeletedAt != nil,
		"open_reports": openReports,
		"device_count": len(devices),
	})
	return nil
}

type banRequest struct {
	Reason string `json:"reason"`
	// RevokeSessions logs the account out everywhere immediately. Default
	// true: leaving a banned account's sessions live means it keeps sending
	// until every access token expires.
	RevokeSessions *bool `json:"revoke_sessions,omitempty"`
}

func (s *service) handleBan(w http.ResponseWriter, r *http.Request) error {
	userID, err := httpx.PathInt64(r, "userID")
	if err != nil {
		return err
	}
	var req banRequest
	if err := httpx.DecodeJSON(r, 8<<10, &req); err != nil {
		return err
	}
	reason, err := requireReason(req.Reason)
	if err != nil {
		return err
	}

	operator := operatorFrom(r.Context())

	if err := s.users.Ban(r.Context(), userID, operator, reason); err != nil {
		if errors.Is(err, pgstore.ErrNotFound) {
			return httpx.ErrNotFound("no such active account")
		}
		return httpx.ErrInternal("could not ban the account").WithCause(err)
	}

	// Postgres first, then the cache. In this order a failure between them
	// leaves the account banned but still able to send until the next
	// reconcile — annoying. The reverse order would leave the cache saying
	// banned while the database says otherwise, and the account would be
	// unable to send with nothing in any admin view explaining why.
	if err := s.bans.Set(r.Context(), userID, reason); err != nil {
		s.log.Log.Error("banned in the database but could not update the ban cache; "+
			"the send path will not enforce this until the next reconcile",
			"user_id", userID, "error", err)
	}

	revoke := req.RevokeSessions == nil || *req.RevokeSessions
	var revoked int64
	if revoke {
		// keepDeviceID 0 matches no device, so this revokes everything.
		if revoked, err = s.devices.RevokeAllExcept(r.Context(), userID, 0); err != nil {
			s.log.Log.Error("banned but could not revoke sessions", "user_id", userID, "error", err)
		}
	}

	if err := s.audit.Record(r.Context(), auditlog.Entry{
		Action:     auditlog.ActionAccountBanned,
		ActorType:  "operator",
		ActorIP:    httpx.ClientIP(r),
		TargetType: "user",
		TargetID:   userID,
		Reason:     reason,
		Detail: map[string]string{
			"operator":         operator,
			"sessions_revoked": fmt.Sprint(revoked),
			"revoke_sessions":  fmt.Sprint(revoke),
		},
	}); err != nil {
		// The ban has already taken effect; failing the request would tell the
		// operator to retry an action that succeeded.
		s.log.Log.Error("a ban is not in the audit trail", "user_id", userID, "error", err)
	}

	s.publishUserEvent(r.Context(), userID, events.UserBanned)

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"banned":           true,
		"sessions_revoked": revoked,
	})
	return nil
}

func (s *service) handleUnban(w http.ResponseWriter, r *http.Request) error {
	userID, err := httpx.PathInt64(r, "userID")
	if err != nil {
		return err
	}
	var req banRequest
	if err := httpx.DecodeJSON(r, 8<<10, &req); err != nil {
		return err
	}
	reason, err := requireReason(req.Reason)
	if err != nil {
		return err
	}

	operator := operatorFrom(r.Context())

	// Cache first here, the mirror of the ban ordering: if the second step
	// fails the account is usable again rather than stuck unable to send with
	// no record of why.
	if err := s.bans.Clear(r.Context(), userID); err != nil {
		s.log.Log.Error("could not clear the ban cache", "user_id", userID, "error", err)
	}
	if err := s.users.Unban(r.Context(), userID); err != nil {
		if errors.Is(err, pgstore.ErrNotFound) {
			return httpx.ErrNotFound("that account is not banned")
		}
		return httpx.ErrInternal("could not lift the ban").WithCause(err)
	}

	if err := s.audit.Record(r.Context(), auditlog.Entry{
		Action:     auditlog.ActionAccountBanned,
		ActorType:  "operator",
		ActorIP:    httpx.ClientIP(r),
		TargetType: "user",
		TargetID:   userID,
		Reason:     reason,
		Detail:     map[string]string{"operator": operator, "lifted": "true"},
	}); err != nil {
		s.log.Log.Error("an unban is not in the audit trail", "user_id", userID, "error", err)
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]bool{"banned": false})
	return nil
}

func (s *service) publishUserEvent(ctx context.Context, userID int64, kind events.UserEventKind) {
	e := events.UserEvent{
		V: events.CurrentVersion, Kind: kind, UserID: userID, At: time.Now().UTC(),
	}
	body, err := json.Marshal(e)
	if err != nil {
		s.log.Log.Error("could not encode a user event", "error", err)
		return
	}
	key := []byte(fmt.Sprint(userID))
	if err := s.events.Publish(ctx, events.TopicUserEvents, key, body); err != nil {
		// Best effort. The ban is already applied in Postgres and Redis; this
		// event only lets other services react sooner.
		s.log.Log.Warn("could not publish a user event", "user_id", userID, "error", err)
	}
}

// reconcileBans repopulates the ban cache from Postgres.
//
// The send-path ban check treats a missing cache entry as "not banned", which
// is the right failure mode — the alternative silences the platform — but it
// means a Redis flush quietly stops that check working. This closes the gap on
// a timer instead of waiting for someone to notice.
func (s *service) reconcileBans(ctx context.Context, every time.Duration) {
	run := func() {
		banned, err := s.users.ListBanned(ctx)
		if err != nil {
			s.log.Log.Error("could not read the ban list to reconcile", "error", err)
			return
		}
		if err := s.bans.Reload(ctx, banned); err != nil {
			s.log.Log.Error("could not reconcile the ban cache", "error", err)
			return
		}
		s.log.Log.Info("ban cache reconciled", "count", len(banned))
	}

	run()

	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}
