// Command mediaproc turns uploaded objects into the derivatives clients need.
//
// It consumes media.processing and, per job: scans for malware, generates
// thumbnails, probes and transcodes video, and promotes avatars into the
// public bucket where the CDN can cache them.
//
// It is the only consumer that downloads object bytes, which makes it the one
// place hostile input is parsed. That shapes everything about how it runs: a
// separate image with ffmpeg, a non-root read-only container, every capability
// dropped, hard timeouts on every subprocess, and a virus scan before any
// derivative is published.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/pervagans/messaging-app/pkg/app"
	"github.com/pervagans/messaging-app/pkg/auditlog"
	"github.com/pervagans/messaging-app/pkg/config"
	"github.com/pervagans/messaging-app/pkg/events"
	"github.com/pervagans/messaging-app/pkg/gcsx"
	"github.com/pervagans/messaging-app/pkg/kafkax"
	"github.com/pervagans/messaging-app/pkg/logx"
	"github.com/pervagans/messaging-app/pkg/mediaproc"
	"github.com/segmentio/kafka-go"
)

func main() {
	app.Run("mediaproc", run)
}

type consumer struct {
	gcs        *gcsx.Client
	scanner    mediaproc.Scanner
	transcoder *mediaproc.Transcoder
	producer   *kafkax.Producer
	// audit records blocked malware. A detection is a security event about a
	// specific account, and the pod log that currently carries it rotates
	// away — the audit trail is what survives long enough to show a pattern.
	audit *auditlog.Logger

	publicBucket string
	// maxDownloadBytes bounds what we are willing to pull into the pod.
	maxDownloadBytes int64
	// workDir is an emptyDir volume with a size limit, so a runaway
	// transcode fills a bounded volume rather than the node's disk.
	workDir string
}

func run(ctx context.Context, a *app.App) error {
	gcsCfg := gcsx.DefaultConfig()
	gcsCfg.MediaBucket = config.String("MEDIA_BUCKET", "")
	gcsCfg.PublicBucket = config.String("PUBLIC_BUCKET", "")
	gcsCfg.CDNHost = config.String("CDN_HOST", "")
	gcsCfg.SignerServiceAccount = config.String("MEDIA_SIGNER_SERVICE_ACCOUNT", "")
	if gcsCfg.MediaBucket == "" {
		return errors.New("MEDIA_BUCKET is required")
	}

	client, err := gcsx.Connect(ctx, gcsCfg)
	if err != nil {
		return fmt.Errorf("cloud storage: %w", err)
	}
	a.OnShutdown("gcs", client.Close)
	a.Health.Register("gcs", client.Ping)

	scanner, err := buildScanner(ctx, a)
	if err != nil {
		return err
	}
	a.Log.Info("virus scanner ready", "provider", scanner.Name())

	// ffmpeg is optional: an image-only deployment does not need it, and
	// failing to start would be wrong. Video jobs are rejected explicitly
	// instead of silently skipped.
	transcoder, err := mediaproc.NewTranscoder()
	if err != nil {
		if !errors.Is(err, mediaproc.ErrFFmpegMissing) {
			return err
		}
		a.Log.Warn("ffmpeg not found; video jobs will be rejected")
		transcoder = nil
	}

	workDir := config.String("WORK_DIR", os.TempDir())
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return fmt.Errorf("work directory: %w", err)
	}

	c := &consumer{
		gcs:              client,
		scanner:          scanner,
		transcoder:       transcoder,
		publicBucket:     gcsCfg.PublicBucket,
		maxDownloadBytes: int64(config.Int("MAX_DOWNLOAD_BYTES", 512<<20)),
		workDir:          workDir,
	}

	kafkaCfg := kafkax.Config{
		Brokers:  config.Strings("KAFKA_BROKERS", []string{"localhost:9092"}),
		UseOAuth: config.Bool("KAFKA_OAUTH", a.Cfg.Env != "dev"),
		TLS:      config.Bool("KAFKA_TLS", a.Cfg.Env != "dev"),
		ClientID: "mediaproc",
	}
	producer, err := kafkax.NewProducer(kafkaCfg, kafkax.DefaultProducerOptions())
	if err != nil {
		return fmt.Errorf("kafka producer: %w", err)
	}
	a.OnShutdown("kafka-producer", producer.Close)
	c.producer = producer
	c.audit = auditlog.New(producer, config.String("HOSTNAME", "mediaproc-0"))

	kc, err := kafkax.NewConsumer(kafkaCfg, kafkax.ConsumerOptions{
		Topic: events.TopicMediaProcessing,
		Group: config.String("KAFKA_GROUP", "mediaproc"),
		// FirstOffset: a job that was queued and never processed leaves a
		// message with no thumbnail, which is visible to the user.
		StartOffset: kafka.FirstOffset,
		// Few retries with a long backoff. Each attempt downloads the object
		// and may run ffmpeg, so retrying aggressively multiplies real cost.
		MaxRetries:  3,
		RetryBase:   5 * time.Second,
		RetryMax:    2 * time.Minute,
		DLQProducer: producer,
		// One job at a time per pod: transcoding is CPU-bound and running
		// several concurrently just makes them all slower.
		MaxBytes: 1 << 20,
	}, a.Log)
	if err != nil {
		return fmt.Errorf("kafka consumer: %w", err)
	}
	a.OnShutdown("kafka-consumer", kc.Close)

	go func() {
		if err := kc.Run(ctx, c.handle); err != nil {
			a.Log.Error("mediaproc stopped", "error", err)
		}
	}()

	return nil
}

func buildScanner(ctx context.Context, a *app.App) (mediaproc.Scanner, error) {
	provider := config.String("SCANNER_PROVIDER", "clamav")

	switch provider {
	case "clamav":
		clam := mediaproc.NewClamAV(config.String("CLAMAV_ADDR", "127.0.0.1:3310"))
		if err := clam.Ping(ctx); err != nil {
			return nil, fmt.Errorf("clamav: %w", err)
		}
		a.Health.Register("clamav", clam.Ping)
		return clam, nil

	case "noop":
		// A silently disabled scanner is worse than no scanner: it looks like
		// the file was checked.
		if a.Cfg.Env == "prod" {
			return nil, errors.New(
				"SCANNER_PROVIDER=noop is not allowed in production; every uploaded file would be served unscanned")
		}
		a.Log.Warn("virus scanning is DISABLED (SCANNER_PROVIDER=noop)")
		return mediaproc.NoopScanner{}, nil
	}

	return nil, fmt.Errorf("unknown SCANNER_PROVIDER %q (want clamav|noop)", provider)
}

// handle processes one job.
//
// Order matters: scan first, then derive. Publishing a thumbnail of a file
// that turns out to be malware would put an attacker-controlled artefact on
// the CDN before we knew what it was.
func (c *consumer) handle(ctx context.Context, m kafka.Message) error {
	var job events.MediaJob
	if err := json.Unmarshal(m.Value, &job); err != nil {
		return fmt.Errorf("%w: malformed media job: %v", kafkax.ErrSkip, err)
	}
	if job.Media.Object == "" {
		return kafkax.ErrSkip
	}

	log := logx.From(ctx).With("upload_id", job.UploadID, "object", job.Media.Object)

	attrs, err := c.gcs.Attrs(ctx, job.Media.Object)
	if err != nil {
		if errors.Is(err, gcsx.ErrNotFound) {
			// The upload was abandoned or the object was already deleted.
			// Retrying will not conjure it into existence.
			log.Info("object no longer exists; dropping the job")
			return kafkax.ErrSkip
		}
		return fmt.Errorf("read object attributes: %w", err)
	}
	if attrs.Size > c.maxDownloadBytes {
		return fmt.Errorf("%w: object of %d bytes exceeds the %d byte processing limit",
			kafkax.ErrSkip, attrs.Size, c.maxDownloadBytes)
	}

	work, err := os.MkdirTemp(c.workDir, "job-*")
	if err != nil {
		return fmt.Errorf("create work directory: %w", err)
	}
	defer os.RemoveAll(work)

	localPath := filepath.Join(work, "source"+path.Ext(job.Media.Object))
	if err := c.download(ctx, job.Media.Object, localPath); err != nil {
		return fmt.Errorf("download object: %w", err)
	}

	// --- 1. Scan -----------------------------------------------------------
	if hasOp(job.Ops, "scan") {
		f, err := os.Open(localPath)
		if err != nil {
			return err
		}
		result, scanErr := c.scanner.Scan(ctx, f, attrs.Size)
		_ = f.Close()

		if scanErr != nil {
			// An unreachable scanner must retry, never pass the file through.
			return fmt.Errorf("scan: %w", scanErr)
		}
		if !result.Clean {
			log.Warn("malware detected; deleting the object",
				"threat", result.Threat, "owner_id", job.OwnerID)
			if err := c.gcs.Delete(ctx, job.Media.Object); err != nil {
				return fmt.Errorf("delete infected object: %w", err)
			}
			c.publishQuarantine(ctx, job, result.Threat)

			// Audited, because this is the one thing this consumer does that
			// is a statement about a person: an account uploaded malware. One
			// detection is usually a forwarded file; a dozen from one account
			// is the account, and only a durable record shows the difference.
			if c.audit != nil {
				if err := c.audit.Record(ctx, auditlog.Entry{
					Action:     auditlog.ActionMalwareBlocked,
					ActorType:  "system",
					TargetType: "user",
					TargetID:   job.OwnerID,
					Detail: map[string]string{
						"threat": result.Threat,
						"mime":   job.Media.MimeType,
						"size":   fmt.Sprint(attrs.Size),
					},
				}); err != nil {
					// Not fatal. The file is already deleted, which is the part
					// that protects people; retrying the whole job to re-record
					// it would re-download and re-scan a deleted object.
					log.Error("malware was blocked but the detection is not in the audit trail",
						"error", err)
				}
			}

			// The job is complete: the file is gone and there is nothing to
			// derive from it.
			return nil
		}
	}

	// --- 2. Derive ---------------------------------------------------------
	kind := kindOf(job.Media.MimeType)
	switch kind {
	case "image":
		if err := c.processImage(ctx, job, localPath, log); err != nil {
			return err
		}
	case "video":
		if c.transcoder == nil {
			return fmt.Errorf("%w: this deployment has no ffmpeg, so video jobs cannot run",
				kafkax.ErrSkip)
		}
		if err := c.processVideo(ctx, job, localPath, work, log); err != nil {
			return err
		}
	default:
		log.Debug("no derivatives for this media type", "mime", job.Media.MimeType)
	}

	log.Info("media job complete", "ops", job.Ops)
	return nil
}

func (c *consumer) download(ctx context.Context, object, dst string) error {
	r, err := c.gcs.NewReader(ctx, object)
	if err != nil {
		return err
	}
	defer r.Close()

	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer f.Close()

	// LimitReader as a second guard: the attribute check above could race a
	// re-upload, and an unbounded copy into a bounded volume is a disk-full.
	if _, err := io.Copy(f, io.LimitReader(r, c.maxDownloadBytes+1)); err != nil {
		return err
	}
	return f.Sync()
}

func (c *consumer) processImage(ctx context.Context, job events.MediaJob, localPath string, log logger) error {
	src, err := os.ReadFile(localPath)
	if err != nil {
		return err
	}

	info, err := mediaproc.Probe(strings.NewReader(string(src)))
	if err != nil {
		// A file that declares image/jpeg and does not decode is either
		// corrupt or an attempt to reach a decoder with something else.
		// Neither is retryable.
		return fmt.Errorf("%w: %v", kafkax.ErrSkip, err)
	}

	var thumbs []events.MediaVariant
	for _, spec := range mediaproc.DefaultThumbnails {
		// Do not upscale: a 64px avatar needs no 320px and 1280px variants.
		if spec.MaxDim > info.Width && spec.MaxDim > info.Height && spec.Name != "_s" {
			continue
		}

		data, thumbInfo, err := mediaproc.Thumbnail(src, spec)
		if err != nil {
			return fmt.Errorf("%w: thumbnail %s: %v", kafkax.ErrSkip, spec.Name, err)
		}

		object := variantObject(job.Media.Object, spec.Name, ".jpg")
		if err := c.gcs.Upload(ctx, object, data, "image/jpeg", "public, max-age=31536000, immutable"); err != nil {
			return fmt.Errorf("upload thumbnail %s: %w", spec.Name, err)
		}

		thumbs = append(thumbs, events.MediaVariant{
			Name: spec.Name, Object: object, MimeType: "image/jpeg",
			Width: thumbInfo.Width, Height: thumbInfo.Height, SizeBytes: int64(len(data)),
		})
		log.Debug("thumbnail generated", "variant", spec.Name, "bytes", len(data))
	}

	// Avatars and chat photos go to the public bucket so the CDN can cache
	// them: everyone in a group fetches the same avatar, and re-signing a URL
	// per viewer would defeat the cache entirely.
	if hasOp(job.Ops, "publish_public") && c.publicBucket != "" {
		for _, v := range thumbs {
			publicObject := strings.TrimPrefix(v.Object, "photo/")
			if err := c.gcs.Copy(ctx, v.Object, c.publicBucket, publicObject,
				"public, max-age=31536000, immutable"); err != nil {
				return fmt.Errorf("promote %s to the public bucket: %w", v.Name, err)
			}
		}
		log.Info("variants promoted to the public bucket", "count", len(thumbs))
	}

	return c.publishComplete(ctx, job, events.MediaDerived{
		Width: info.Width, Height: info.Height, Variants: thumbs,
	})
}

func (c *consumer) processVideo(ctx context.Context, job events.MediaJob, localPath, work string, log logger) error {
	info, err := c.transcoder.ProbeVideo(ctx, localPath)
	if err != nil {
		return fmt.Errorf("%w: %v", kafkax.ErrSkip, err)
	}
	log.Debug("video probed",
		"width", info.Width, "height", info.Height,
		"duration_ms", info.DurationMS, "codec", info.Codec)

	derived := events.MediaDerived{
		Width:      info.Width,
		Height:     info.Height,
		DurationMS: info.DurationMS,
	}

	// A poster frame, so a video in a chat list is not a black rectangle.
	if hasOp(job.Ops, "thumbnail") {
		frame, err := c.transcoder.VideoThumbnail(ctx, localPath, 640)
		if err != nil {
			log.Warn("could not extract a poster frame", "error", err)
		} else {
			object := variantObject(job.Media.Object, "_poster", ".jpg")
			if err := c.gcs.Upload(ctx, object, frame, "image/jpeg",
				"public, max-age=31536000, immutable"); err != nil {
				return fmt.Errorf("upload poster frame: %w", err)
			}
			derived.Variants = append(derived.Variants, events.MediaVariant{
				Name: "_poster", Object: object, MimeType: "image/jpeg",
				SizeBytes: int64(len(frame)),
			})
		}
	}

	if hasOp(job.Ops, "transcode") {
		for _, profile := range mediaproc.DefaultProfiles {
			// Skip a rendition that would be an upscale, and skip transcoding
			// entirely when the source is already H.264 at or below the
			// target height — re-encoding it would only lose quality.
			if info.Height <= profile.MaxHeight && info.Codec == "h264" {
				log.Debug("source already meets the profile; skipping transcode",
					"profile", profile.Name)
				continue
			}

			outPath := filepath.Join(work, "out"+profile.Name+".mp4")
			if err := c.transcoder.Transcode(ctx, localPath, outPath, profile); err != nil {
				return fmt.Errorf("transcode %s: %w", profile.Name, err)
			}

			data, err := os.ReadFile(outPath)
			if err != nil {
				return err
			}
			object := variantObject(job.Media.Object, profile.Name, ".mp4")
			if err := c.gcs.Upload(ctx, object, data, "video/mp4", ""); err != nil {
				return fmt.Errorf("upload rendition %s: %w", profile.Name, err)
			}

			derived.Variants = append(derived.Variants, events.MediaVariant{
				Name: profile.Name, Object: object, MimeType: "video/mp4",
				Height: profile.MaxHeight, SizeBytes: int64(len(data)),
			})
			log.Info("video transcoded", "profile", profile.Name, "bytes", len(data))
		}
	}

	return c.publishComplete(ctx, job, derived)
}

// publishComplete tells the chat service the derivatives exist, so it can
// attach them to the message.
func (c *consumer) publishComplete(ctx context.Context, job events.MediaJob, derived events.MediaDerived) error {
	evt := events.MediaProcessed{
		V: events.CurrentVersion, UploadID: job.UploadID, OwnerID: job.OwnerID,
		Object: job.Media.Object, Derived: derived, ProcessedAt: time.Now().UTC(),
	}
	body, err := json.Marshal(evt)
	if err != nil {
		return err
	}
	return c.producer.Publish(ctx, events.TopicMediaProcessed, []byte(job.UploadID), body)
}

func (c *consumer) publishQuarantine(ctx context.Context, job events.MediaJob, threat string) {
	evt := events.MediaProcessed{
		V: events.CurrentVersion, UploadID: job.UploadID, OwnerID: job.OwnerID,
		Object: job.Media.Object, Quarantined: true, Threat: threat,
		ProcessedAt: time.Now().UTC(),
	}
	body, err := json.Marshal(evt)
	if err != nil {
		return
	}
	// Detached: the object is already deleted and the notification must go
	// out even if the request context is finished.
	bg, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	_ = c.producer.Publish(bg, events.TopicMediaProcessed, []byte(job.UploadID), body)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

type logger interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
}

func hasOp(ops []string, want string) bool {
	for _, o := range ops {
		if o == want {
			return true
		}
	}
	return false
}

func kindOf(mime string) string {
	switch {
	case strings.HasPrefix(mime, "image/"):
		return "image"
	case strings.HasPrefix(mime, "video/"):
		return "video"
	case strings.HasPrefix(mime, "audio/"):
		return "audio"
	}
	return "file"
}

// variantObject derives a sibling object path, preserving the directory
// prefix so lifecycle rules apply to derivatives as well as originals.
func variantObject(original, suffix, ext string) string {
	dir := path.Dir(original)
	base := strings.TrimSuffix(path.Base(original), path.Ext(original))
	return path.Join(dir, base+suffix+ext)
}
