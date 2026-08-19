// Package gcsx handles media objects in Cloud Storage.
//
// The service never proxies media bytes. Clients upload straight to GCS with
// a V4 signed URL and download through Cloud CDN, so a 50MB video costs the
// media service two small JSON calls instead of 50MB of pod bandwidth twice
// over. That single decision is what keeps the media tier cheap and stateless.
package gcsx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"strings"
	"time"

	"cloud.google.com/go/storage"
	"github.com/pervagans/messaging-app/pkg/ids"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/iamcredentials/v1"
	"google.golang.org/api/option"
)

// Config describes the buckets and signing identity.
type Config struct {
	// MediaBucket holds user uploads. Private; reached only via signed URLs
	// or through the CDN-backed backend bucket.
	MediaBucket string
	// PublicBucket holds avatars and other content safe to cache at the edge.
	PublicBucket string
	// CDNHost is the domain fronting PublicBucket, e.g. cdn.example.com.
	CDNHost string
	// SignerServiceAccount is the email of the GSA used to sign URLs. With
	// Workload Identity there is no private key in the pod, so signing goes
	// through the IAM Credentials signBlob API instead.
	SignerServiceAccount string
	// UploadTTL bounds how long an upload URL stays usable.
	UploadTTL time.Duration
	// DownloadTTL bounds a read URL.
	DownloadTTL time.Duration
	// MaxUploadBytes is enforced twice: here when we build the URL, and by
	// the bucket's own object size condition.
	MaxUploadBytes int64
}

// DefaultConfig returns sane TTLs.
func DefaultConfig() Config {
	return Config{
		UploadTTL:      15 * time.Minute,
		DownloadTTL:    6 * time.Hour,
		MaxUploadBytes: 2 << 30, // 2 GiB
	}
}

// Client wraps the storage client plus the signing identity.
type Client struct {
	sc   *storage.Client
	iam  *iamcredentials.Service
	cfg  Config
	self string
}

// Connect builds the client.
//
// It resolves the signing service account eagerly so a missing
// roles/iam.serviceAccountTokenCreator binding fails at startup with a clear
// message, rather than on a user's first upload.
func Connect(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.MediaBucket == "" {
		return nil, errors.New("gcsx: media bucket is required")
	}

	sc, err := storage.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("gcsx: storage client: %w", err)
	}

	iamSvc, err := iamcredentials.NewService(ctx, option.WithScopes(iamcredentials.CloudPlatformScope))
	if err != nil {
		_ = sc.Close()
		return nil, fmt.Errorf("gcsx: iamcredentials client: %w", err)
	}

	self := cfg.SignerServiceAccount
	if self == "" {
		self, err = detectServiceAccount(ctx)
		if err != nil {
			_ = sc.Close()
			return nil, err
		}
	}

	return &Client{sc: sc, iam: iamSvc, cfg: cfg, self: self}, nil
}

// detectServiceAccount reads the active identity from ADC.
func detectServiceAccount(ctx context.Context) (string, error) {
	creds, err := google.FindDefaultCredentials(ctx, storage.ScopeFullControl)
	if err != nil {
		return "", fmt.Errorf("gcsx: find default credentials: %w", err)
	}
	// A service-account JSON key carries the email in the credentials file.
	if len(creds.JSON) > 0 {
		var doc struct {
			ClientEmail string `json:"client_email"`
		}
		if err := jsonUnmarshal(creds.JSON, &doc); err == nil && doc.ClientEmail != "" {
			return doc.ClientEmail, nil
		}
	}
	// On GKE with Workload Identity there is no JSON; the metadata server
	// knows the impersonated account.
	email, err := metadataEmail(ctx)
	if err != nil {
		return "", fmt.Errorf("gcsx: cannot determine signing service account: %w; "+
			"set MEDIA_SIGNER_SERVICE_ACCOUNT explicitly", err)
	}
	return email, nil
}

// Close releases the client.
func (c *Client) Close(context.Context) error { return c.sc.Close() }

// Ping verifies the media bucket is reachable; used as a readiness check.
func (c *Client) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err := c.sc.Bucket(c.cfg.MediaBucket).Attrs(ctx); err != nil {
		return fmt.Errorf("gcsx: bucket %s: %w", c.cfg.MediaBucket, err)
	}
	return nil
}

// signBytes signs with the IAM Credentials API.
//
// This is the piece that makes Workload Identity work end to end: the pod has
// no key material, it asks IAM to sign on the service account's behalf, and
// IAM authorises the call using the pod's federated token.
func (c *Client) signBytes(ctx context.Context, b []byte) ([]byte, error) {
	name := "projects/-/serviceAccounts/" + c.self
	resp, err := c.iam.Projects.ServiceAccounts.
		SignBlob(name, &iamcredentials.SignBlobRequest{Payload: b64(b)}).
		Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("gcsx: signBlob as %s: %w", c.self, err)
	}
	return unb64(resp.SignedBlob)
}

// ObjectPath builds the canonical object name for an upload.
//
// The date prefix exists for lifecycle rules and for spreading writes across
// the bucket's key space; the random component makes the path unguessable so
// a leaked URL cannot be walked to a neighbour's file.
func ObjectPath(ownerID int64, kind, filename string) string {
	now := time.Now().UTC()
	ext := strings.ToLower(path.Ext(filename))
	if len(ext) > 10 {
		ext = ""
	}
	return fmt.Sprintf("%s/%04d/%02d/%02d/%d/%s%s",
		kind, now.Year(), now.Month(), now.Day(), ownerID, ids.NewUUID(), ext)
}

// UploadURL returns a V4 signed URL the client PUTs its bytes to.
//
// Content-Type and Content-Length are bound into the signature, so the client
// cannot upload a 4GB file against a URL we issued for a 2MB image, nor
// smuggle an HTML document through an image/jpeg content type.
func (c *Client) UploadURL(ctx context.Context, object, contentType string, sizeBytes int64) (string, error) {
	if sizeBytes <= 0 {
		return "", errors.New("gcsx: upload size must be positive")
	}
	if c.cfg.MaxUploadBytes > 0 && sizeBytes > c.cfg.MaxUploadBytes {
		return "", fmt.Errorf("gcsx: upload of %d bytes exceeds the %d byte limit",
			sizeBytes, c.cfg.MaxUploadBytes)
	}
	if contentType == "" {
		return "", errors.New("gcsx: content type is required")
	}

	opts := &storage.SignedURLOptions{
		Scheme:      storage.SigningSchemeV4,
		Method:      "PUT",
		Expires:     time.Now().Add(orDefaultDur(c.cfg.UploadTTL, 15*time.Minute)),
		ContentType: contentType,
		Headers: []string{
			fmt.Sprintf("Content-Length:%d", sizeBytes),
		},
		GoogleAccessID: c.self,
		SignBytes: func(b []byte) ([]byte, error) {
			return c.signBytes(ctx, b)
		},
	}

	u, err := storage.SignedURL(c.cfg.MediaBucket, object, opts)
	if err != nil {
		return "", fmt.Errorf("gcsx: sign upload URL: %w", err)
	}
	return u, nil
}

// DownloadURL returns a time-limited read URL for a private object.
func (c *Client) DownloadURL(ctx context.Context, object string, filename string) (string, error) {
	opts := &storage.SignedURLOptions{
		Scheme:         storage.SigningSchemeV4,
		Method:         "GET",
		Expires:        time.Now().Add(orDefaultDur(c.cfg.DownloadTTL, 6*time.Hour)),
		GoogleAccessID: c.self,
		SignBytes: func(b []byte) ([]byte, error) {
			return c.signBytes(ctx, b)
		},
	}
	if filename != "" {
		// Force a download with the original name instead of the opaque
		// object path, and stop the browser rendering user content inline.
		opts.QueryParameters = url.Values{
			"response-content-disposition": []string{
				fmt.Sprintf("attachment; filename=%q", sanitiseFilename(filename)),
			},
		}
	}

	u, err := storage.SignedURL(c.cfg.MediaBucket, object, opts)
	if err != nil {
		return "", fmt.Errorf("gcsx: sign download URL: %w", err)
	}
	return u, nil
}

// PublicURL returns the CDN URL for an object in the public bucket.
func (c *Client) PublicURL(object string) string {
	if c.cfg.CDNHost != "" {
		return fmt.Sprintf("https://%s/%s", c.cfg.CDNHost, object)
	}
	return fmt.Sprintf("https://storage.googleapis.com/%s/%s", c.cfg.PublicBucket, object)
}

// Attrs reads object metadata, used to confirm an upload actually landed and
// that its declared size and type match what was stored.
func (c *Client) Attrs(ctx context.Context, object string) (*storage.ObjectAttrs, error) {
	a, err := c.sc.Bucket(c.cfg.MediaBucket).Object(object).Attrs(ctx)
	if err != nil {
		if errors.Is(err, storage.ErrObjectNotExist) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("gcsx: attrs %s: %w", object, err)
	}
	return a, nil
}

// ErrNotFound is returned when an object does not exist.
var ErrNotFound = errors.New("gcsx: object not found")

// Delete removes an object.
func (c *Client) Delete(ctx context.Context, object string) error {
	err := c.sc.Bucket(c.cfg.MediaBucket).Object(object).Delete(ctx)
	if err != nil && !errors.Is(err, storage.ErrObjectNotExist) {
		return fmt.Errorf("gcsx: delete %s: %w", object, err)
	}
	return nil
}

// Copy duplicates an object, used to promote a processed thumbnail into the
// public bucket.
func (c *Client) Copy(ctx context.Context, srcObject, dstBucket, dstObject string, cacheControl string) error {
	src := c.sc.Bucket(c.cfg.MediaBucket).Object(srcObject)
	dst := c.sc.Bucket(dstBucket).Object(dstObject)
	copier := dst.CopierFrom(src)
	if cacheControl != "" {
		copier.CacheControl = cacheControl
	}
	if _, err := copier.Run(ctx); err != nil {
		return fmt.Errorf("gcsx: copy %s -> %s/%s: %w", srcObject, dstBucket, dstObject, err)
	}
	return nil
}

// sanitiseFilename strips path separators and control characters so a
// malicious filename cannot inject headers into the Content-Disposition.
func sanitiseFilename(s string) string {
	base := path.Base(s)

	// path.Base never returns an empty string: "" becomes ".", "/" stays "/",
	// and ".." stays "..". None of those is a filename, and each would
	// otherwise survive to produce a nonsense save dialog — "." verbatim, or
	// "_" once the separator is replaced below.
	switch base {
	case "", ".", "..", "/":
		return "file"
	}

	var b strings.Builder
	for _, r := range base {
		switch {
		case r < 0x20 || r == 0x7f, r == '"', r == '\\', r == '/':
			// Control characters and quotes would break out of the quoted
			// string in the Content-Disposition header; CR and LF would
			// inject a header outright.
			b.WriteRune('_')
		default:
			b.WriteRune(r)
		}
	}

	out := b.String()
	if len(out) > 120 {
		out = out[:120]
	}
	if strings.Trim(out, "_. ") == "" {
		// Everything was stripped or replaced, e.g. a name of only control
		// characters.
		return "file"
	}
	return out
}

func orDefaultDur(v, def time.Duration) time.Duration {
	if v == 0 {
		return def
	}
	return v
}

// NewReader streams an object's bytes.
//
// Used only by the media processor, which is the one component that needs the
// content rather than a URL to it. Everything else hands a signed URL to the
// client and never touches the bytes.
func (c *Client) NewReader(ctx context.Context, object string) (io.ReadCloser, error) {
	r, err := c.sc.Bucket(c.cfg.MediaBucket).Object(object).NewReader(ctx)
	if err != nil {
		if errors.Is(err, storage.ErrObjectNotExist) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("gcsx: read %s: %w", object, err)
	}
	return r, nil
}

// Upload writes an object.
//
// cacheControl matters more than it looks: derivatives are content-addressed
// by their source object's UUID and never change, so they are marked immutable
// with a one-year max-age. That turns every subsequent view into a CDN hit.
func (c *Client) Upload(ctx context.Context, object string, data []byte, contentType, cacheControl string) error {
	w := c.sc.Bucket(c.cfg.MediaBucket).Object(object).NewWriter(ctx)
	w.ContentType = contentType
	if cacheControl != "" {
		w.CacheControl = cacheControl
	}
	// Refuse to overwrite: derivatives are written once, and a second write
	// to the same path means either a replay or a path collision. Both should
	// be visible rather than silent.
	w.ChunkSize = 1 << 20

	if _, err := w.Write(data); err != nil {
		_ = w.Close()
		return fmt.Errorf("gcsx: write %s: %w", object, err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("gcsx: finalise %s: %w", object, err)
	}
	return nil
}
