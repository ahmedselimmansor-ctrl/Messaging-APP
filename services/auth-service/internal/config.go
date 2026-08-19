package auth

import (
	"fmt"
	"time"

	"github.com/pervagans/messaging-app/pkg/authn"
	"github.com/pervagans/messaging-app/pkg/config"
	"github.com/pervagans/messaging-app/pkg/kafkax"
	"github.com/pervagans/messaging-app/pkg/pgstore"
	"github.com/pervagans/messaging-app/pkg/redisx"
)

// Config is the auth service's full configuration.
type Config struct {
	Base config.Base

	Postgres pgstore.Config
	Redis    redisx.Config
	Kafka    kafkax.Config
	Issuer   authn.IssuerConfig
	SMS      SMSConfig

	// CodeLength is the number of digits in a verification code. Five digits
	// with a 5-attempt cap and a 5-minute expiry gives an attacker a 1-in-
	// 20,000 chance per challenge, which the per-phone rate limit then caps at
	// a handful of challenges an hour.
	CodeLength int
	// CodeTTL is how long a challenge stays valid.
	CodeTTL time.Duration
	// MaxCodeAttempts is how many wrong guesses burn a challenge.
	MaxCodeAttempts int

	// ContactPepper keys the HMAC clients use to hash address-book numbers,
	// so a plaintext address book never reaches our request logs. See
	// pgstore.PhoneHash for exactly what this does and does not buy.
	ContactPepper []byte

	// TestPhonePrefix lets automated tests and app-store reviewers sign in
	// with a fixed code instead of a real SMS. Empty in production, and the
	// service refuses to start if it is set while ENV=prod.
	TestPhonePrefix string
	TestPhoneCode   string
}

// SMSConfig selects and configures the delivery channel for codes.
type SMSConfig struct {
	// Provider is "log" (development), "noop" or "webhook".
	//
	// There is no bundled Twilio/Vonage client on purpose: which aggregator a
	// deployment uses is a commercial decision, and every one of them is an
	// HTTP POST. The webhook provider posts to whatever endpoint you point it
	// at, so integrating a real provider is configuration, not code.
	Provider string
	// WebhookURL receives {"phone":"+20...","code":"12345","ttl_seconds":300}.
	WebhookURL string
	// WebhookAuthHeader is sent as the Authorization header, sourced from
	// Secret Manager.
	WebhookAuthHeader string
	Timeout           time.Duration
}

// LoadConfig reads the service configuration from the environment.
func LoadConfig(base config.Base) (Config, error) {
	dsn, err := config.MustString("POSTGRES_DSN")
	if err != nil {
		return Config{}, err
	}
	signingKey, err := config.MustSecret("JWT_SIGNING_KEY_PEM")
	if err != nil {
		return Config{}, err
	}
	keyID, err := config.MustString("JWT_SIGNING_KEY_ID")
	if err != nil {
		return Config{}, err
	}

	pg := pgstore.DefaultConfig()
	pg.DSN = dsn
	pg.MaxConns = int32(config.Int("POSTGRES_MAX_CONNS", 20))

	c := Config{
		Base:     base,
		Postgres: pg,
		Redis: redisx.Config{
			Addrs:    config.Strings("REDIS_ADDRS", []string{"localhost:6379"}),
			Cluster:  config.Bool("REDIS_CLUSTER", false),
			Username: config.String("REDIS_USERNAME", ""),
			Password: config.Secret("REDIS_PASSWORD", ""),
			TLS:      config.Bool("REDIS_TLS", false),
		},
		Kafka: kafkax.Config{
			Brokers:  config.Strings("KAFKA_BROKERS", []string{"localhost:9092"}),
			UseOAuth: config.Bool("KAFKA_OAUTH", base.Env != "dev"),
			TLS:      config.Bool("KAFKA_TLS", base.Env != "dev"),
			ClientID: "auth-service",
		},
		Issuer: authn.IssuerConfig{
			PrivateKeyPEM: signingKey,
			KeyID:         keyID,
			Issuer:        config.String("JWT_ISSUER", "messaging"),
			Audience:      config.String("JWT_AUDIENCE", "messaging-api"),
			AccessTTL:     config.Duration("JWT_ACCESS_TTL", 15*time.Minute),
			RefreshTTL:    config.Duration("JWT_REFRESH_TTL", 60*24*time.Hour),
		},
		SMS: SMSConfig{
			Provider:          config.String("SMS_PROVIDER", "log"),
			WebhookURL:        config.String("SMS_WEBHOOK_URL", ""),
			WebhookAuthHeader: config.Secret("SMS_WEBHOOK_AUTH", ""),
			Timeout:           config.Duration("SMS_TIMEOUT", 5*time.Second),
		},
		ContactPepper:   []byte(config.String("CONTACT_PEPPER", "")),
		CodeLength:      config.Int("OTP_CODE_LENGTH", 5),
		CodeTTL:         config.Duration("OTP_TTL", 5*time.Minute),
		MaxCodeAttempts: config.Int("OTP_MAX_ATTEMPTS", 5),
		TestPhonePrefix: config.String("TEST_PHONE_PREFIX", ""),
		TestPhoneCode:   config.String("TEST_PHONE_CODE", ""),
	}

	if base.Env == "prod" {
		if c.SMS.Provider == "log" || c.SMS.Provider == "noop" {
			return Config{}, fmt.Errorf(
				"auth: SMS_PROVIDER=%q is not allowed in production; codes would never reach users",
				c.SMS.Provider)
		}
		if c.TestPhonePrefix != "" {
			return Config{}, fmt.Errorf(
				"auth: TEST_PHONE_PREFIX must not be set in production; it is a permanent auth bypass")
		}
	}
	if base.Env == "prod" && len(c.ContactPepper) < 16 {
		return Config{}, fmt.Errorf(
			"auth: CONTACT_PEPPER must be at least 16 bytes in production; " +
				"an empty pepper makes every submitted address-book hash trivially reversible")
	}
	if len(c.ContactPepper) == 0 {
		// Development only. A fixed value keeps hashes stable across restarts
		// so a local client does not have to re-import on every boot.
		c.ContactPepper = []byte("local-development-pepper")
	}
	if c.SMS.Provider == "webhook" && c.SMS.WebhookURL == "" {
		return Config{}, fmt.Errorf("auth: SMS_PROVIDER=webhook requires SMS_WEBHOOK_URL")
	}
	if c.CodeLength < 4 || c.CodeLength > 8 {
		return Config{}, fmt.Errorf("auth: OTP_CODE_LENGTH must be 4..8, got %d", c.CodeLength)
	}

	return c, nil
}
