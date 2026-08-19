// Command chat-service owns the message write path and chat management.
//
// It is the only service that accepts a message, and the only one that
// allocates a sequence number. Everything downstream — persistence, fanout,
// push, search — reads what this service publishes to Kafka.
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/pervagans/messaging-app/pkg/app"
	"github.com/pervagans/messaging-app/pkg/auditlog"
	"github.com/pervagans/messaging-app/pkg/authn"
	"github.com/pervagans/messaging-app/pkg/cassandrax"
	"github.com/pervagans/messaging-app/pkg/config"
	"github.com/pervagans/messaging-app/pkg/httpx"
	"github.com/pervagans/messaging-app/pkg/ids"
	"github.com/pervagans/messaging-app/pkg/kafkax"
	"github.com/pervagans/messaging-app/pkg/pgstore"
	"github.com/pervagans/messaging-app/pkg/ratelimit"
	"github.com/pervagans/messaging-app/pkg/redisx"
	chat "github.com/pervagans/messaging-app/services/chat-service/internal"
)

func main() {
	app.Run("chat-service", run)
}

func run(ctx context.Context, a *app.App) error {
	cfg, err := chat.LoadConfig(a.Cfg)
	if err != nil {
		return err
	}

	db, err := pgstore.Connect(ctx, cfg.Postgres)
	if err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	a.OnShutdown("postgres", db.Close)
	a.Health.Register("postgres", db.Ping)

	cass, err := cassandrax.Connect(ctx, cfg.Cassandra)
	if err != nil {
		return fmt.Errorf("cassandra: %w", err)
	}
	a.OnShutdown("cassandra", cass.Close)
	a.Health.Register("cassandra", cass.Ping)

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
	// Kafka closes first so buffered messages flush before we drop the
	// database sessions the flush path might need.
	a.OnShutdown("kafka", producer.Close)
	a.Health.Register("kafka", producer.Ping)

	verifier, err := authn.LoadVerifier(ctx, a.Log)
	if err != nil {
		return fmt.Errorf("token verifier: %w", err)
	}
	// Keep the key set current so a signing-key rotation in the auth service
	// does not need a redeploy here.
	go verifier.Run(ctx, 15*time.Minute)

	snowflake, err := ids.NewSnowflake(ids.NodeFromHostname(config.String("HOSTNAME", "chat-0")))
	if err != nil {
		return fmt.Errorf("id generator: %w", err)
	}

	messages := cass.Messages()

	svc := &chat.Service{
		Cfg:       cfg,
		Log:       a.Log,
		Chats:     db.ChatsRepo(),
		Members:   db.MembersRepo(),
		Users:     db.UsersRepo(),
		Sequences: db.SequencesRepo(),
		Messages:  messages,
		Redis:     rdb,
		// The sequence allocator falls back to Cassandra's stored maximum
		// when the Redis counter is missing, so a Memorystore failover cannot
		// make us reuse sequence numbers.
		Seq:      rdb.Seq(messages.MaxSeq),
		Bus:      rdb.PubSub(),
		MemCache: rdb.Members(cfg.MembersCacheTTL),
		Producer: producer,
		IDs:      snowflake,
		Verifier: verifier,
		// Fail open: a Redis outage must degrade rate limiting, not stop
		// people sending messages.
		Limiter: ratelimit.New(rdb.Raw(), true),
		// Each replica keeps its own hash chain, identified by pod name, so
		// audit writes never contend across pods.
		Audit:       auditlog.New(producer, config.String("HOSTNAME", "chat-0")),
		Reports:     db.ReportsRepo(),
		Devices:     db.DevicesRepo(),
		Contacts:    db.ContactsRepo(),
		Blocks:      db.BlocksRepo(),
		SecretChats: db.SecretChatsRepo(),
		// Bans are mirrored here so the send path never touches Postgres.
		// Authoritative enforcement is at token issuance in the auth service.
		BanCache: rdb.Bans(config.Duration("BAN_CACHE_TTL", 0)),
	}

	svc.Init()

	srv := httpx.NewServer(a.Cfg.HTTPAddr, svc.Routes())
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			a.Log.Error("http listener failed", "error", err)
		}
	}()
	a.OnShutdown("http", srv.Shutdown)

	return nil
}
