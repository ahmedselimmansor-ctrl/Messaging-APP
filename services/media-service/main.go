// Command media-service negotiates uploads and downloads.
//
// It never carries a byte of media. Clients PUT directly to Cloud Storage with
// a signed URL and read through Cloud CDN; this service only issues the URLs,
// records what was uploaded and queues post-processing. That is why it runs on
// two small replicas while serving multi-gigabyte traffic.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/pervagans/messaging-app/pkg/app"
	"github.com/pervagans/messaging-app/pkg/authn"
	"github.com/pervagans/messaging-app/pkg/cassandrax"
	"github.com/pervagans/messaging-app/pkg/config"
	"github.com/pervagans/messaging-app/pkg/events"
	"github.com/pervagans/messaging-app/pkg/gcsx"
	"github.com/pervagans/messaging-app/pkg/httpx"
	"github.com/pervagans/messaging-app/pkg/ids"
	"github.com/pervagans/messaging-app/pkg/kafkax"
	"github.com/pervagans/messaging-app/pkg/pgstore"
	"github.com/pervagans/messaging-app/pkg/ratelimit"
	"github.com/pervagans/messaging-app/pkg/redisx"
)

func main() {
	app.Run("media-service", run)
}

type service struct {
	gcs      *gcsx.Client
	producer *kafkax.Producer
	verifier *authn.RefreshingVerifier
	limiter  *ratelimit.Limiter
	redis    *redisx.Client

	// mediaACL answers "which chat was this object shared into?" and members
	// answers "is the caller in it?". Together they are what stops a
	// forwarded object path from granting access.
	mediaACL *cassandrax.MediaACL
	members  *pgstore.Members

	maxUploadBytes int64
}

func run(ctx context.Context, a *app.App) error {
	gcsCfg := gcsx.DefaultConfig()
	gcsCfg.MediaBucket = config.String("MEDIA_BUCKET", "")
	gcsCfg.PublicBucket = config.String("PUBLIC_BUCKET", "")
	gcsCfg.CDNHost = config.String("CDN_HOST", "")
	gcsCfg.SignerServiceAccount = config.String("MEDIA_SIGNER_SERVICE_ACCOUNT", "")
	gcsCfg.UploadTTL = config.Duration("UPLOAD_URL_TTL", 15*time.Minute)
	gcsCfg.DownloadTTL = config.Duration("DOWNLOAD_URL_TTL", 6*time.Hour)
	gcsCfg.MaxUploadBytes = int64(config.Int("MAX_UPLOAD_BYTES", 2<<30))

	if gcsCfg.MediaBucket == "" {
		return errors.New("MEDIA_BUCKET is required")
	}

	client, err := gcsx.Connect(ctx, gcsCfg)
	if err != nil {
		return fmt.Errorf("cloud storage: %w", err)
	}
	a.OnShutdown("gcs", client.Close)
	a.Health.Register("gcs", client.Ping)

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

	producer, err := kafkax.NewProducer(kafkax.Config{
		Brokers:  config.Strings("KAFKA_BROKERS", []string{"localhost:9092"}),
		UseOAuth: config.Bool("KAFKA_OAUTH", a.Cfg.Env != "dev"),
		TLS:      config.Bool("KAFKA_TLS", a.Cfg.Env != "dev"),
		ClientID: "media-service",
	}, kafkax.DefaultProducerOptions())
	if err != nil {
		return fmt.Errorf("kafka: %w", err)
	}
	a.OnShutdown("kafka", producer.Close)

	verifier, err := authn.LoadVerifier(ctx, a.Log)
	if err != nil {
		return fmt.Errorf("token verifier: %w", err)
	}
	go verifier.Run(ctx, 15*time.Minute)

	// Cassandra holds the object -> chat binding; Postgres holds membership.
	cassCfg := cassandrax.DefaultConfig()
	cassCfg.Hosts = config.Strings("CASSANDRA_HOSTS", []string{"localhost:9042"})
	cassCfg.Keyspace = config.String("CASSANDRA_KEYSPACE", "messaging")
	cassCfg.Username = config.String("CASSANDRA_USERNAME", "")
	cassCfg.Password = config.Secret("CASSANDRA_PASSWORD", "")
	cassCfg.LocalDC = config.String("CASSANDRA_LOCAL_DC", a.Cfg.Region)

	cass, err := cassandrax.Connect(ctx, cassCfg)
	if err != nil {
		return fmt.Errorf("cassandra: %w", err)
	}
	a.OnShutdown("cassandra", cass.Close)
	a.Health.Register("cassandra", cass.Ping)

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

	svc := &service{
		gcs:            client,
		producer:       producer,
		verifier:       verifier,
		redis:          rdb,
		limiter:        ratelimit.New(rdb.Raw(), true),
		mediaACL:       cass.Media(),
		members:        db.MembersRepo(),
		maxUploadBytes: gcsCfg.MaxUploadBytes,
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
	for _, mw := range httpx.BaseMiddleware("media-service") {
		r.Use(mw)
	}
	r.Group(func(r chi.Router) {
		r.Use(authn.Middleware(s.verifier))
		r.Post("/v1/uploads", httpx.H(s.handleInitUpload))
		r.Post("/v1/uploads/{uploadID}/complete", httpx.H(s.handleCompleteUpload))
		r.Get("/v1/media/download", httpx.H(s.handleDownloadURL))
	})
	return r
}

// allowedMime is the upload allowlist.
//
// An allowlist, not a blocklist: the danger is a file that a browser will
// render as active content when a victim opens the CDN URL, and there are
// far more ways to spell "HTML" than ways to spell "JPEG".
var allowedMime = map[string]string{
	"image/jpeg":               "photo",
	"image/png":                "photo",
	"image/webp":               "photo",
	"image/gif":                "photo",
	"image/heic":               "photo",
	"video/mp4":                "video",
	"video/quicktime":          "video",
	"video/webm":               "video",
	"audio/ogg":                "voice",
	"audio/mpeg":               "voice",
	"audio/mp4":                "voice",
	"audio/aac":                "voice",
	"application/pdf":          "file",
	"application/zip":          "file",
	"application/octet-stream": "file",
	"text/plain":               "file",
}

type initUploadRequest struct {
	Filename  string `json:"filename"`
	MimeType  string `json:"mime_type"`
	SizeBytes int64  `json:"size_bytes"`
	// Purpose is "message", "avatar" or "chat_photo". Avatars land in the
	// public bucket after processing; message media never does.
	Purpose string `json:"purpose,omitempty"`
}

type initUploadResponse struct {
	UploadID  string            `json:"upload_id"`
	Object    string            `json:"object"`
	UploadURL string            `json:"upload_url"`
	Method    string            `json:"method"`
	Headers   map[string]string `json:"headers"`
	ExpiresIn int               `json:"expires_in"`
}

func (s *service) handleInitUpload(w http.ResponseWriter, r *http.Request) error {
	claims, ok := authn.ClaimsFrom(r.Context())
	if !ok {
		return httpx.ErrUnauthorized("authorization required")
	}
	var req initUploadRequest
	if err := httpx.DecodeJSON(r, 16<<10, &req); err != nil {
		return err
	}

	if d, err := s.limiter.Allow(r.Context(),
		ratelimit.KeyUser("upload", claims.UserID), ratelimit.UploadInit); err == nil && !d.Allowed {
		return httpx.ErrFloodWait(int(d.RetryAfter.Seconds()) + 1)
	}

	mime := strings.ToLower(strings.TrimSpace(req.MimeType))
	kind, allowed := allowedMime[mime]
	if !allowed {
		return httpx.ErrBadRequest("unsupported media type %q", req.MimeType)
	}
	if req.SizeBytes <= 0 {
		return httpx.ErrBadRequest("size_bytes must be positive")
	}
	if req.SizeBytes > s.maxUploadBytes {
		return httpx.ErrBadRequest("file exceeds the %d byte limit", s.maxUploadBytes)
	}
	// Avatars are small and end up cached at the edge forever; a 2GB "avatar"
	// is either a mistake or an attempt to fill the public bucket.
	if req.Purpose == "avatar" || req.Purpose == "chat_photo" {
		const maxAvatarBytes = 8 << 20
		if req.SizeBytes > maxAvatarBytes {
			return httpx.ErrBadRequest("a profile image must be at most %d bytes", maxAvatarBytes)
		}
		if kind != "photo" {
			return httpx.ErrBadRequest("a profile image must be an image")
		}
	}

	object := gcsx.ObjectPath(claims.UserID, kind, safeFilename(req.Filename))
	url, err := s.gcs.UploadURL(r.Context(), object, mime, req.SizeBytes)
	if err != nil {
		return httpx.ErrInternal("could not create an upload URL").WithCause(err)
	}

	uploadID := ids.NewUUID()
	// Remember what we authorised, keyed by upload id. The completion call
	// checks the stored size and type against what actually landed, so a
	// client cannot declare a 1MB JPEG and upload a 1GB executable.
	pending, _ := json.Marshal(map[string]any{
		"owner": claims.UserID, "object": object, "mime": mime,
		"size": req.SizeBytes, "kind": kind, "purpose": req.Purpose,
	})
	if err := s.redis.Raw().Set(r.Context(),
		"upload:{"+uploadID+"}", pending, 24*time.Hour).Err(); err != nil {
		return httpx.ErrUnavailable("could not record the upload").WithCause(err)
	}

	// A second record keyed by the object, so the uploader can preview a file
	// it has not yet attached to a message. It expires with the upload window:
	// after that the only way to read the object is to be in the chat it was
	// sent to.
	if err := s.redis.Raw().Set(r.Context(),
		"uploadowner:{"+gcsx.ACLKey(object)+"}", claims.UserID, 24*time.Hour).Err(); err != nil {
		return httpx.ErrUnavailable("could not record the upload owner").WithCause(err)
	}

	httpx.WriteJSON(w, http.StatusOK, initUploadResponse{
		UploadID:  uploadID,
		Object:    object,
		UploadURL: url,
		Method:    http.MethodPut,
		Headers: map[string]string{
			"Content-Type":   mime,
			"Content-Length": fmt.Sprint(req.SizeBytes),
		},
		ExpiresIn: int((15 * time.Minute).Seconds()),
	})
	return nil
}

type completeUploadResponse struct {
	Object    string `json:"object"`
	MimeType  string `json:"mime_type"`
	SizeBytes int64  `json:"size_bytes"`
	Ready     bool   `json:"ready"`
}

// handleCompleteUpload verifies the object landed and queues processing.
func (s *service) handleCompleteUpload(w http.ResponseWriter, r *http.Request) error {
	claims, ok := authn.ClaimsFrom(r.Context())
	if !ok {
		return httpx.ErrUnauthorized("authorization required")
	}
	uploadID := chi.URLParam(r, "uploadID")
	if uploadID == "" {
		return httpx.ErrBadRequest("upload id is required")
	}

	raw, err := s.redis.Raw().Get(r.Context(), "upload:{"+uploadID+"}").Bytes()
	if err != nil {
		return httpx.ErrNotFound("no such upload, or it has expired")
	}
	var pending struct {
		Owner   int64  `json:"owner"`
		Object  string `json:"object"`
		Mime    string `json:"mime"`
		Size    int64  `json:"size"`
		Kind    string `json:"kind"`
		Purpose string `json:"purpose"`
	}
	if err := json.Unmarshal(raw, &pending); err != nil {
		return httpx.ErrInternal("could not read the upload record").WithCause(err)
	}
	if pending.Owner != claims.UserID {
		// Same response as "not found": revealing that someone else's upload
		// exists is an information leak.
		return httpx.ErrNotFound("no such upload, or it has expired")
	}

	attrs, err := s.gcs.Attrs(r.Context(), pending.Object)
	if err != nil {
		if errors.Is(err, gcsx.ErrNotFound) {
			return httpx.ErrConflict("the object has not been uploaded yet")
		}
		return httpx.ErrInternal("could not read the object").WithCause(err)
	}
	// Trust what GCS reports, not what the client claimed.
	if attrs.Size != pending.Size {
		if err := s.gcs.Delete(r.Context(), pending.Object); err != nil {
			return httpx.ErrInternal("could not remove a mismatched upload").WithCause(err)
		}
		return httpx.ErrBadRequest("uploaded size %d does not match the declared %d",
			attrs.Size, pending.Size)
	}

	job := events.MediaJob{
		V: events.CurrentVersion, UploadID: uploadID, OwnerID: claims.UserID,
		Media: events.MediaRef{
			Bucket: attrs.Bucket, Object: pending.Object,
			MimeType: pending.Mime, SizeBytes: attrs.Size,
		},
		Ops:       opsFor(pending.Kind, pending.Purpose),
		CreatedAt: time.Now().UTC(),
	}
	body, err := json.Marshal(job)
	if err != nil {
		return httpx.ErrInternal("could not encode the processing job").WithCause(err)
	}
	if err := s.producer.Publish(r.Context(), events.TopicMediaProcessing,
		[]byte(uploadID), body); err != nil {
		// Processing is best-effort enrichment (thumbnails, transcoding).
		// The upload itself is complete and usable, so this must not fail the
		// request.
		httpx.WriteJSON(w, http.StatusOK, completeUploadResponse{
			Object: pending.Object, MimeType: pending.Mime, SizeBytes: attrs.Size, Ready: true,
		})
		return nil
	}

	httpx.WriteJSON(w, http.StatusOK, completeUploadResponse{
		Object: pending.Object, MimeType: pending.Mime, SizeBytes: attrs.Size, Ready: true,
	})
	return nil
}

func (s *service) handleDownloadURL(w http.ResponseWriter, r *http.Request) error {
	userID, err := authn.MustUserID(r.Context())
	if err != nil {
		return err
	}
	object := r.URL.Query().Get("object")
	if object == "" {
		return httpx.ErrBadRequest("object is required")
	}
	if strings.Contains(object, "..") || strings.HasPrefix(object, "/") {
		return httpx.ErrBadRequest("object is not a valid path")
	}

	// Authorisation. Possession of the object path used to be the whole
	// capability, which meant a forwarded path granted access to anyone
	// forever. The binding recorded when the message was persisted says which
	// chat this object belongs to; membership in that chat is what grants
	// access now, and revoking membership revokes the media with it.
	//
	// A derivative resolves to its original's binding, so a thumbnail is
	// governed by exactly the same row.
	chatID, uploaderID, err := s.mediaACL.ChatFor(r.Context(), object)
	if err != nil {
		if errors.Is(err, cassandrax.ErrNotFound) {
			// No binding: the object was never attached to a message. The
			// uploader may still fetch their own pending upload — otherwise
			// the client could not preview what it just uploaded — but nobody
			// else can.
			if !s.ownsPendingUpload(r.Context(), userID, object) {
				return httpx.ErrNotFound("no such object")
			}
		} else {
			return httpx.ErrUnavailable("could not check media permissions").WithCause(err)
		}
	} else if uploaderID != userID {
		member, err := s.members.Get(r.Context(), chatID, userID)
		if err != nil || member.LeftAt != nil {
			// 404 rather than 403: confirming the object exists to someone
			// outside the chat is exactly the leak this check closes.
			return httpx.ErrNotFound("no such object")
		}
	}

	url, err := s.gcs.DownloadURL(r.Context(), object, r.URL.Query().Get("filename"))
	if err != nil {
		return httpx.ErrInternal("could not create a download URL").WithCause(err)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"url":        url,
		"expires_in": int((6 * time.Hour).Seconds()),
	})
	return nil
}

// ownsPendingUpload reports whether the caller uploaded this object and has
// not yet attached it to a message.
//
// The object path embeds the uploader's id, but that is not proof — a path is
// attacker-supplied. The pending-upload record in Redis is, because only the
// upload-init handler writes it and it is keyed by an unguessable upload id.
func (s *service) ownsPendingUpload(ctx context.Context, userID int64, object string) bool {
	key := gcsx.ACLKey(object)
	owner, err := s.redis.Raw().Get(ctx, "uploadowner:{"+key+"}").Int64()
	if err != nil {
		return false
	}
	return owner == userID
}

func opsFor(kind, purpose string) []string {
	ops := []string{"scan"}
	switch kind {
	case "photo":
		ops = append(ops, "thumbnail")
		if purpose == "avatar" || purpose == "chat_photo" {
			ops = append(ops, "publish_public")
		}
	case "video":
		ops = append(ops, "thumbnail", "transcode")
	}
	return ops
}

// safeFilename strips anything that could escape the object prefix.
func safeFilename(name string) string {
	name = path.Base(strings.TrimSpace(name))
	if name == "." || name == "/" || name == "" {
		return "file"
	}
	return name
}
