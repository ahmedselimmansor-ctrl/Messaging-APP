// Command search-service answers message search queries.
//
// It is read-only: the indexer is the only writer. That split means a search
// outage cannot corrupt the index, and a reindex cannot be triggered by a
// user request.
//
// Every query is ACL-filtered inside Elasticsearch on the document's member
// list, so a user can only match chats they are in. Post-filtering the
// results would leak through the total count and the pagination.
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/pervagans/messaging-app/pkg/app"
	"github.com/pervagans/messaging-app/pkg/authn"
	"github.com/pervagans/messaging-app/pkg/config"
	"github.com/pervagans/messaging-app/pkg/httpx"
	"github.com/pervagans/messaging-app/pkg/pgstore"
	"github.com/pervagans/messaging-app/pkg/ratelimit"
	"github.com/pervagans/messaging-app/pkg/redisx"
	"github.com/pervagans/messaging-app/pkg/searchx"
)

func main() {
	app.Run("search-service", run)
}

type service struct {
	search   *searchx.Client
	users    *pgstore.Users
	verifier *authn.RefreshingVerifier
	limiter  *ratelimit.Limiter
}

func run(ctx context.Context, a *app.App) error {
	sc, err := searchx.Connect(ctx, searchx.Config{
		Addresses: config.Strings("ELASTICSEARCH_ADDRS", []string{"http://localhost:9200"}),
		Username:  config.String("ELASTICSEARCH_USERNAME", ""),
		Password:  config.Secret("ELASTICSEARCH_PASSWORD", ""),
		APIKey:    config.String("ELASTICSEARCH_API_KEY", ""),
		CloudID:   config.String("ELASTICSEARCH_CLOUD_ID", ""),
		Index:     config.String("ELASTICSEARCH_INDEX", "messages"),
	})
	if err != nil {
		return fmt.Errorf("elasticsearch: %w", err)
	}
	a.Health.Register("elasticsearch", sc.Ping)

	dsn, err := config.MustString("POSTGRES_DSN")
	if err != nil {
		return err
	}
	pgCfg := pgstore.DefaultConfig()
	pgCfg.DSN = dsn
	pgCfg.MaxConns = int32(config.Int("POSTGRES_MAX_CONNS", 10))

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

	verifier, err := authn.LoadVerifier(ctx, a.Log)
	if err != nil {
		return fmt.Errorf("token verifier: %w", err)
	}
	go verifier.Run(ctx, 15*time.Minute)

	svc := &service{
		search:   sc,
		users:    db.UsersRepo(),
		verifier: verifier,
		// Fail open: search is a convenience, and a Redis outage should
		// degrade the limiter rather than remove the feature.
		limiter: ratelimit.New(rdb.Raw(), true),
	}

	srv := httpx.NewServer(a.Cfg.HTTPAddr, svc.routes())
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			a.Log.Error("http listener failed", "error", err)
		}
	}()
	a.OnShutdown("http", srv.Shutdown)

	return nil
}

func (s *service) routes() http.Handler {
	r := chi.NewRouter()
	for _, mw := range httpx.BaseMiddleware("search-service") {
		r.Use(mw)
	}

	r.Group(func(r chi.Router) {
		r.Use(authn.Middleware(s.verifier))
		r.Get("/v1/search/messages", httpx.H(s.handleSearchMessages))
		r.Get("/v1/search/users", httpx.H(s.handleSearchUsers))
	})

	// The gateway's route, for search over the realtime connection.
	r.Group(func(r chi.Router) {
		r.Use(s.internalIdentity)
		r.Post("/internal/v1/search/messages", httpx.H(s.handleSearchMessagesInternal))
	})

	return r
}

func (s *service) internalIdentity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var userID int64
		if _, err := fmt.Sscanf(r.Header.Get("X-User-Id"), "%d", &userID); err != nil || userID == 0 {
			httpx.WriteError(w, r, httpx.ErrUnauthorized("X-User-Id is required on internal calls"))
			return
		}
		claims := &authn.Claims{Type: authn.AccessToken, UserID: userID}
		next.ServeHTTP(w, r.WithContext(authn.WithClaims(r.Context(), claims)))
	})
}

// searchLimit is tighter than a normal read.
//
// A full-text query with fuzziness is an order of magnitude more expensive
// than a key lookup, and an unbounded one is a cheap way to make the
// Elasticsearch cluster everyone's problem.
var searchLimit = ratelimit.Limit{Burst: 20, Rate: 2}

func (s *service) handleSearchMessages(w http.ResponseWriter, r *http.Request) error {
	claims, ok := authn.ClaimsFrom(r.Context())
	if !ok {
		return httpx.ErrUnauthorized("authorization required")
	}

	q := searchx.Query{
		UserID:   claims.UserID,
		Text:     r.URL.Query().Get("q"),
		ChatID:   httpx.QueryInt64(r, "chat_id", 0),
		SenderID: httpx.QueryInt64(r, "sender_id", 0),
		Limit:    httpx.QueryInt(r, "limit", 20, 1, 100),
		Offset:   httpx.QueryInt(r, "offset", 0, 0, 1000),
	}
	if from := r.URL.Query().Get("from"); from != "" {
		if t, err := time.Parse(time.RFC3339, from); err == nil {
			q.From = t
		}
	}
	if to := r.URL.Query().Get("to"); to != "" {
		if t, err := time.Parse(time.RFC3339, to); err == nil {
			q.To = t
		}
	}

	return s.runSearch(w, r, q)
}

type internalSearchRequest struct {
	Text     string `json:"q"`
	ChatID   int64  `json:"chat_id,omitempty"`
	SenderID int64  `json:"sender_id,omitempty"`
	Limit    int    `json:"limit,omitempty"`
	Offset   int    `json:"offset,omitempty"`
}

func (s *service) handleSearchMessagesInternal(w http.ResponseWriter, r *http.Request) error {
	claims, ok := authn.ClaimsFrom(r.Context())
	if !ok {
		return httpx.ErrUnauthorized("authorization required")
	}
	var req internalSearchRequest
	if err := httpx.DecodeJSON(r, 16<<10, &req); err != nil {
		return err
	}

	return s.runSearch(w, r, searchx.Query{
		UserID:   claims.UserID,
		Text:     req.Text,
		ChatID:   req.ChatID,
		SenderID: req.SenderID,
		Limit:    req.Limit,
		Offset:   req.Offset,
	})
}

func (s *service) runSearch(w http.ResponseWriter, r *http.Request, q searchx.Query) error {
	if d, err := s.limiter.Allow(r.Context(),
		ratelimit.KeyUser("search", q.UserID), searchLimit); err == nil && !d.Allowed {
		return httpx.ErrFloodWait(int(d.RetryAfter.Seconds()) + 1)
	}

	results, err := s.search.SearchMessages(r.Context(), q)
	if err != nil {
		if errors.Is(err, searchx.ErrEmptyQuery) {
			return httpx.ErrBadRequest("a search query is required")
		}
		return httpx.ErrUnavailable("search is unavailable").WithCause(err)
	}

	httpx.WriteJSON(w, http.StatusOK, results)
	return nil
}

// handleSearchUsers is a prefix search over public usernames.
//
// Deliberately username-only. Searching by display name or phone number would
// turn the user directory into a scraping target, and phone numbers are
// discoverable through contact import — where the caller has to already know
// the number.
func (s *service) handleSearchUsers(w http.ResponseWriter, r *http.Request) error {
	claims, ok := authn.ClaimsFrom(r.Context())
	if !ok {
		return httpx.ErrUnauthorized("authorization required")
	}

	prefix := strings.TrimSpace(r.URL.Query().Get("q"))
	if len(prefix) < 3 {
		// A one-character prefix would enumerate the directory a page at a
		// time.
		return httpx.ErrBadRequest("the search prefix must be at least 3 characters")
	}

	if d, err := s.limiter.Allow(r.Context(),
		ratelimit.KeyUser("search_users", claims.UserID), searchLimit); err == nil && !d.Allowed {
		return httpx.ErrFloodWait(int(d.RetryAfter.Seconds()) + 1)
	}

	users, err := s.users.SearchByUsername(r.Context(), prefix, httpx.QueryInt(r, "limit", 20, 1, 50))
	if err != nil {
		return httpx.ErrInternal("user search failed").WithCause(err)
	}

	// Only the public fields. The phone number is never part of a search
	// result, whatever the caller asked for.
	type publicUser struct {
		ID          int64   `json:"id"`
		Username    *string `json:"username,omitempty"`
		DisplayName string  `json:"display_name"`
		AvatarObj   *string `json:"avatar_object,omitempty"`
	}
	out := make([]publicUser, 0, len(users))
	for _, u := range users {
		out = append(out, publicUser{
			ID: u.ID, Username: u.Username,
			DisplayName: u.DisplayName, AvatarObj: u.AvatarObj,
		})
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{"users": out})
	return nil
}
