// Command auth-service issues and refreshes credentials.
//
// It owns phone verification, account creation, JWT issuance and device
// (session) management. It is the only service that holds the signing key, and
// the only one that writes to the users and devices tables.
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/pervagans/messaging-app/pkg/app"
	"github.com/pervagans/messaging-app/pkg/auditlog"
	"github.com/pervagans/messaging-app/pkg/authn"
	"github.com/pervagans/messaging-app/pkg/config"
	"github.com/pervagans/messaging-app/pkg/events"
	"github.com/pervagans/messaging-app/pkg/httpx"
	"github.com/pervagans/messaging-app/pkg/ids"
	"github.com/pervagans/messaging-app/pkg/kafkax"
	"github.com/pervagans/messaging-app/pkg/pgstore"
	"github.com/pervagans/messaging-app/pkg/ratelimit"
	"github.com/pervagans/messaging-app/pkg/redisx"
	auth "github.com/pervagans/messaging-app/services/auth-service/internal"
)

func main() {
	app.Run("auth-service", run)
}

func run(ctx context.Context, a *app.App) error {
	cfg, err := auth.LoadConfig(a.Cfg)
	if err != nil {
		return err
	}

	db, err := pgstore.Connect(ctx, cfg.Postgres)
	if err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	a.OnShutdown("postgres", db.Close)
	a.Health.Register("postgres", db.Ping)

	rdb, err := redisx.Connect(ctx, cfg.Redis)
	if err != nil {
		return fmt.Errorf("redis: %w", err)
	}
	a.OnShutdown("redis", rdb.Close)
	a.Health.Register("redis", rdb.Ping)

	producer, err := kafkax.NewProducer(cfg.Kafka, kafkax.DefaultProducerOptions())
	if err != nil {
		return fmt.Errorf("kafka: %w", err)
	}
	a.OnShutdown("kafka", producer.Close)

	issuer, err := authn.NewIssuer(cfg.Issuer)
	if err != nil {
		return fmt.Errorf("token issuer: %w", err)
	}
	verifier, err := authn.NewVerifierFromIssuer(issuer)
	if err != nil {
		return fmt.Errorf("token verifier: %w", err)
	}

	snowflake, err := ids.NewSnowflake(ids.NodeFromHostname(config.String("HOSTNAME", "auth-0")))
	if err != nil {
		return fmt.Errorf("id generator: %w", err)
	}

	sender, err := auth.NewCodeSender(cfg.SMS, a.Log)
	if err != nil {
		return fmt.Errorf("code sender: %w", err)
	}

	svc := &auth.Service{
		Cfg:      cfg,
		Log:      a.Log,
		Users:    db.UsersRepo(),
		Devices:  db.DevicesRepo(),
		OTP:      db.OTPRepo(),
		Contacts: db.ContactsRepo(),
		Blocks:   db.BlocksRepo(),
		Issuer:   issuer,
		Verifier: verifier,
		IDs:      snowflake,
		Sender:   sender,
		Producer: producer,
		Redis:    rdb,
		// Fail closed: an OTP endpoint that stops rate limiting during a
		// Redis outage is an SMS bill and a brute-force window.
		Limiter: ratelimit.New(rdb.Raw(), false),
		Audit:   auditlog.New(producer, config.String("HOSTNAME", "auth-0")),
	}

	srv := httpx.NewServer(a.Cfg.HTTPAddr, svc.Routes())
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			a.Log.Error("http listener failed", "error", err)
		}
	}()
	a.OnShutdown("http", srv.Shutdown)

	// Announce startup so downstream consumers can invalidate any cached
	// JWKS after a signing-key rotation.
	if err := svc.PublishServiceEvent(ctx, events.UserEvent{
		V: events.CurrentVersion, Kind: "auth_service_started",
	}); err != nil {
		a.Log.Warn("startup event not published", "error", err)
	}

	return nil
}
