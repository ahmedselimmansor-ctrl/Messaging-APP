package chat

import (
	"fmt"
	"strings"
	"time"

	"github.com/gocql/gocql"
	"github.com/pervagans/messaging-app/pkg/cassandrax"
	"github.com/pervagans/messaging-app/pkg/config"
	"github.com/pervagans/messaging-app/pkg/kafkax"
	"github.com/pervagans/messaging-app/pkg/pgstore"
	"github.com/pervagans/messaging-app/pkg/redisx"
)

// Config is the chat service's configuration.
type Config struct {
	Base config.Base

	Postgres  pgstore.Config
	Cassandra cassandrax.Config
	Redis     redisx.Config
	Kafka     kafkax.Config

	// RegionEndpoints maps a region name to that region's chat service.
	//
	// Empty in a single-region deployment, where every chat is local and the
	// proxy path is dead code. Populated as "europe-west1=http://...,me-central1=http://..."
	// once a second region exists.
	RegionEndpoints map[string]string

	// AuthServiceURL is where block checks go. Blocks are account-scoped
	// data owned by the auth service, so the chat service asks rather than
	// reading the table itself.
	AuthServiceURL string

	// JWKSURL is the auth service's key set. Fetched at startup and refreshed
	// periodically so a signing-key rotation does not need a redeploy here.
	JWKSURL   string
	JWTIssuer string
	JWTAud    string

	// MembersCacheTTL is how long a chat's roster stays cached in Redis.
	// Short enough that a removed member loses access quickly, long enough
	// that the send path almost never touches Postgres.
	MembersCacheTTL time.Duration

	// MaxMessageRunes caps a text message. Telegram's limit is 4096; matching
	// it keeps clients interoperable and keeps one message inside a single
	// Cassandra cell comfortably.
	MaxMessageRunes int
	// MaxGroupMembers bounds a group. Beyond this the fanout cost per message
	// stops being linear-but-fine and starts needing a channel's read model.
	MaxGroupMembers int
	// MaxRecipientsInline is how many member ids we are willing to attach to
	// a message event. Above it, downstream consumers re-read the roster
	// instead, because a 200k-member channel would make every event enormous.
	MaxRecipientsInline int
}

// LoadConfig reads the configuration from the environment.
func LoadConfig(base config.Base) (Config, error) {
	dsn, err := config.MustString("POSTGRES_DSN")
	if err != nil {
		return Config{}, err
	}

	pg := pgstore.DefaultConfig()
	pg.DSN = dsn
	pg.MaxConns = int32(config.Int("POSTGRES_MAX_CONNS", 25))

	cass := cassandrax.DefaultConfig()
	cass.Hosts = config.Strings("CASSANDRA_HOSTS", []string{"localhost:9042"})
	cass.Keyspace = config.String("CASSANDRA_KEYSPACE", "messaging")
	cass.Username = config.String("CASSANDRA_USERNAME", "")
	cass.Password = config.Secret("CASSANDRA_PASSWORD", "")
	cass.LocalDC = config.String("CASSANDRA_LOCAL_DC", base.Region)
	if lvl := config.String("CASSANDRA_CONSISTENCY", ""); lvl != "" {
		parsed, err := parseConsistency(lvl)
		if err != nil {
			return Config{}, err
		}
		cass.Consistency = parsed
	}

	return Config{
		Base:      base,
		Postgres:  pg,
		Cassandra: cass,
		Redis: redisx.Config{
			Addrs:    config.Strings("REDIS_ADDRS", []string{"localhost:6379"}),
			Cluster:  config.Bool("REDIS_CLUSTER", false),
			Username: config.String("REDIS_USERNAME", ""),
			Password: config.Secret("REDIS_PASSWORD", ""),
			TLS:      config.Bool("REDIS_TLS", false),
			PoolSize: config.Int("REDIS_POOL_SIZE", 100),
		},
		Kafka: kafkax.Config{
			Brokers:  config.Strings("KAFKA_BROKERS", []string{"localhost:9092"}),
			UseOAuth: config.Bool("KAFKA_OAUTH", base.Env != "dev"),
			TLS:      config.Bool("KAFKA_TLS", base.Env != "dev"),
			ClientID: "chat-service",
		},
		RegionEndpoints:     parseRegionEndpoints(config.String("REGION_ENDPOINTS", "")),
		AuthServiceURL:      config.String("AUTH_SERVICE_URL", "http://auth-service.messaging.svc.cluster.local"),
		JWKSURL:             config.String("JWKS_URL", "http://auth-service.messaging.svc.cluster.local/.well-known/jwks.json"),
		JWTIssuer:           config.String("JWT_ISSUER", "messaging"),
		JWTAud:              config.String("JWT_AUDIENCE", "messaging-api"),
		MembersCacheTTL:     config.Duration("MEMBERS_CACHE_TTL", 5*time.Minute),
		MaxMessageRunes:     config.Int("MAX_MESSAGE_RUNES", 4096),
		MaxGroupMembers:     config.Int("MAX_GROUP_MEMBERS", 200_000),
		MaxRecipientsInline: config.Int("MAX_RECIPIENTS_INLINE", 1000),
	}, nil
}

func parseConsistency(s string) (gocql.Consistency, error) {
	switch s {
	case "ONE":
		return gocql.One, nil
	case "QUORUM":
		return gocql.Quorum, nil
	case "LOCAL_ONE":
		return gocql.LocalOne, nil
	case "LOCAL_QUORUM":
		return gocql.LocalQuorum, nil
	case "ALL":
		return gocql.All, nil
	}
	return 0, fmt.Errorf("chat: unsupported CASSANDRA_CONSISTENCY %q", s)
}

// parseRegionEndpoints reads "region=url,region=url" into a map.
//
// A malformed entry is skipped rather than fatal: a typo in one region's
// endpoint should not stop the service starting and taking traffic for every
// chat homed locally. The proxy path fails loudly when it actually needs the
// missing entry.
func parseRegionEndpoints(raw string) map[string]string {
	out := map[string]string{}
	for _, pair := range strings.Split(raw, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		region, url, ok := strings.Cut(pair, "=")
		if !ok {
			continue
		}
		region, url = strings.TrimSpace(region), strings.TrimSpace(url)
		if region != "" && url != "" {
			out[region] = url
		}
	}
	return out
}
