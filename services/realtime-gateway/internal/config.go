package gateway

import (
	"fmt"
	"time"

	"github.com/pervagans/messaging-app/pkg/config"
	"github.com/pervagans/messaging-app/pkg/kafkax"
	"github.com/pervagans/messaging-app/pkg/redisx"
)

// Config is the realtime gateway's configuration.
type Config struct {
	Base config.Base

	Redis redisx.Config
	Kafka kafkax.Config

	// Listener addresses. All three run in the same pod so a client can move
	// between transports without changing endpoint or losing its session.
	TCPAddr string
	UDPAddr string
	WSAddr  string
	WSPath  string
	// WSAllowedOrigins restricts browser connections.
	WSAllowedOrigins []string

	// ServerKeyPEM is the RSA private key used in the auth-key handshake,
	// sourced from Secret Manager.
	ServerKeyPEM string

	// Upstream services.
	ChatServiceURL string
	AuthServiceURL string
	PresenceURL    string

	// SessionTTL is how long a negotiated auth key stays valid in Redis
	// without use. Long enough that a phone offline for a week reconnects
	// without a fresh handshake; short enough that abandoned keys expire.
	SessionTTL time.Duration

	// PingInterval is how often the gateway expects a client ping. Presence
	// TTL must be comfortably longer than this.
	PingInterval time.Duration
	// IdleTimeout closes a connection that has said nothing.
	IdleTimeout time.Duration
	// HandshakeTimeout bounds an unauthenticated connection's lifetime.
	HandshakeTimeout time.Duration

	// MaxConnectionsPerPod caps concurrent connections. The gateway's memory
	// is dominated by per-connection buffers, so this is the knob that turns
	// "how much RAM does a pod need" into a number.
	MaxConnectionsPerPod int64

	// UpdateQueueSize is the per-connection outbound buffer. A client that
	// cannot keep up loses updates and resyncs on reconnect, which is far
	// better than the pod buffering without bound on its behalf.
	UpdateQueueSize int

	// SaltRotation is how often server salts are rotated.
	SaltRotation time.Duration

	// PodName identifies this pod in presence routing records.
	PodName string
}

// LoadConfig reads the configuration from the environment.
func LoadConfig(base config.Base) (Config, error) {
	serverKey, err := config.MustSecret("MTPROTO_SERVER_KEY_PEM")
	if err != nil {
		return Config{}, fmt.Errorf(
			"%w (generate one with `make gen-mtproto-key` and store it in Secret Manager)", err)
	}

	c := Config{
		Base: base,
		Redis: redisx.Config{
			Addrs:    config.Strings("REDIS_ADDRS", []string{"localhost:6379"}),
			Cluster:  config.Bool("REDIS_CLUSTER", false),
			Username: config.String("REDIS_USERNAME", ""),
			Password: config.Secret("REDIS_PASSWORD", ""),
			TLS:      config.Bool("REDIS_TLS", false),
			PoolSize: config.Int("REDIS_POOL_SIZE", 200),
		},
		Kafka: kafkax.Config{
			Brokers:  config.Strings("KAFKA_BROKERS", []string{"localhost:9092"}),
			UseOAuth: config.Bool("KAFKA_OAUTH", base.Env != "dev"),
			TLS:      config.Bool("KAFKA_TLS", base.Env != "dev"),
			ClientID: "realtime-gateway",
		},

		TCPAddr:          config.String("MTPROTO_TCP_ADDR", ":4443"),
		UDPAddr:          config.String("MTPROTO_UDP_ADDR", ":4443"),
		WSAddr:           config.String("MTPROTO_WS_ADDR", ":8080"),
		WSPath:           config.String("MTPROTO_WS_PATH", "/mtproto"),
		WSAllowedOrigins: config.Strings("WS_ALLOWED_ORIGINS", nil),

		ServerKeyPEM: serverKey,

		ChatServiceURL: config.String("CHAT_SERVICE_URL", "http://chat-service.messaging.svc.cluster.local"),
		AuthServiceURL: config.String("AUTH_SERVICE_URL", "http://auth-service.messaging.svc.cluster.local"),
		PresenceURL:    config.String("PRESENCE_SERVICE_URL", "http://presence-service.messaging.svc.cluster.local"),

		SessionTTL:       config.Duration("SESSION_TTL", 30*24*time.Hour),
		PingInterval:     config.Duration("PING_INTERVAL", 60*time.Second),
		IdleTimeout:      config.Duration("IDLE_TIMEOUT", 150*time.Second),
		HandshakeTimeout: config.Duration("HANDSHAKE_TIMEOUT", 30*time.Second),

		MaxConnectionsPerPod: int64(config.Int("MAX_CONNECTIONS_PER_POD", 40_000)),
		UpdateQueueSize:      config.Int("UPDATE_QUEUE_SIZE", 256),
		SaltRotation:         config.Duration("SALT_ROTATION", time.Hour),
		PodName:              config.String("HOSTNAME", "gateway-0"),
	}

	if c.IdleTimeout <= c.PingInterval {
		return Config{}, fmt.Errorf(
			"IDLE_TIMEOUT (%s) must exceed PING_INTERVAL (%s), or healthy clients get disconnected",
			c.IdleTimeout, c.PingInterval)
	}
	return c, nil
}
