package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSecretPrefersTheFile(t *testing.T) {
	// The file wins. In the cluster both are often set — the environment
	// variable as a leftover default, the file as the real credential — and
	// picking the wrong one authenticates as the wrong role.
	dir := t.TempDir()
	path := filepath.Join(dir, "password")
	if err := os.WriteFile(path, []byte("from-the-file"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("CASSANDRA_PASSWORD", "from-the-environment")
	t.Setenv("CASSANDRA_PASSWORD_FILE", path)

	if got := Secret("CASSANDRA_PASSWORD", "fallback"); got != "from-the-file" {
		t.Errorf("Secret = %q, want the file's contents", got)
	}
}

func TestSecretStripsTheTrailingNewline(t *testing.T) {
	// printf, editors and `echo` all leave one. A password with an invisible
	// newline on the end fails to authenticate in a way that costs hours.
	for _, suffix := range []string{"\n", "\r\n", "\n\n", ""} {
		dir := t.TempDir()
		path := filepath.Join(dir, "password")
		if err := os.WriteFile(path, []byte("s3cret"+suffix), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("K_FILE", path)

		if got := Secret("K", ""); got != "s3cret" {
			t.Errorf("with suffix %q: Secret = %q, want %q", suffix, got, "s3cret")
		}
	}
}

func TestSecretKeepsInternalWhitespace(t *testing.T) {
	// A PEM is multi-line. Trimming must only touch the end, or the key is
	// mangled into something that fails to parse.
	pem := "-----BEGIN PRIVATE KEY-----\nabc\ndef\n-----END PRIVATE KEY-----"
	dir := t.TempDir()
	path := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(path, []byte(pem+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("JWT_SIGNING_KEY_PEM_FILE", path)

	if got := Secret("JWT_SIGNING_KEY_PEM", ""); got != pem {
		t.Errorf("a PEM did not survive the round trip:\n got %q\nwant %q", got, pem)
	}
}

func TestSecretFallsBackToTheEnvironment(t *testing.T) {
	// docker-compose and local development have no CSI driver, so the plain
	// variable has to keep working.
	t.Setenv("REDIS_PASSWORD", "local-dev")
	if got := Secret("REDIS_PASSWORD", ""); got != "local-dev" {
		t.Errorf("Secret = %q, want the environment value", got)
	}
}

func TestSecretUsesTheDefaultWhenNothingIsSet(t *testing.T) {
	if got := Secret("DEFINITELY_NOT_SET_ANYWHERE", "def"); got != "def" {
		t.Errorf("Secret = %q, want the default", got)
	}
}

func TestSecretFallsBackWhenTheFileIsMissingOrEmpty(t *testing.T) {
	// A CSI mount that has not populated yet gives an unreadable path; an
	// empty file is a botched rotation. Neither should yield "" as though it
	// were a deliberate value.
	t.Setenv("K_FILE", filepath.Join(t.TempDir(), "does-not-exist"))
	if got := Secret("K", "fallback"); got != "fallback" {
		t.Errorf("missing file: Secret = %q, want the default", got)
	}

	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("K_FILE", empty)
	if got := Secret("K", "fallback"); got != "fallback" {
		t.Errorf("empty file: Secret = %q, want the default", got)
	}
}

func TestMustSecretReportsBothSources(t *testing.T) {
	_, err := MustSecret("NOT_SET_AT_ALL")
	if err == nil {
		t.Fatal("MustSecret returned nil for an unset secret")
	}
	// The message has to name the file variable too, or an operator who set
	// only the mount path is told the variable is missing and sets that
	// instead — reintroducing the environment-variable exposure.
	msg := err.Error()
	if !contains(msg, "NOT_SET_AT_ALL_FILE") {
		t.Errorf("error does not mention the _FILE form: %v", err)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
