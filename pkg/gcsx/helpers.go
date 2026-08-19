package gcsx

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func unb64(s string) ([]byte, error) {
	out, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("gcsx: decode signature: %w", err)
	}
	return out, nil
}

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

// metadataEmail asks the GKE metadata server which service account this
// workload is running as. Available on every GCE/GKE node; absent locally,
// which is why the caller falls back to an explicit configuration value.
func metadataEmail(ctx context.Context) (string, error) {
	const url = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email"

	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("metadata server returned %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 512))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}
