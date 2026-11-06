package secret

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeConfig(t *testing.T, dir string, mode os.FileMode, body string) string {
	t.Helper()
	path := filepath.Join(dir, "vlt.env")
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := writeConfig(t, dir, 0o600, "# comment\n\nBW_SERVER=\"https://vault.example.com\"\nBW_EMAIL=user@example.com\nexport BW_PASSWORD='s3cret'\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server != "https://vault.example.com" || cfg.Email != "user@example.com" || cfg.Password != "s3cret" {
		t.Fatalf("unexpected config %+v", cfg)
	}
}

func TestLoadRejectsGroupReadable(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, 0o644, "BW_SERVER=x\nBW_EMAIL=y\nBW_PASSWORD=z\n")
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadRejectsWorldReadableDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := writeConfig(t, dir, 0o600, "BW_SERVER=x\nBW_EMAIL=y\nBW_PASSWORD=z\n")
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "chmod 700") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadPasswordFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	pw := filepath.Join(dir, "master")
	if err := os.WriteFile(pw, []byte("from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := writeConfig(t, dir, 0o600, "BW_SERVER=x\nBW_EMAIL=y\nBW_PASSWORD_FILE="+pw+"\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Password != "from-file" {
		t.Fatalf("password = %q", cfg.Password)
	}
}

func TestLoadMissingKey(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, 0o600, "BW_SERVER=x\nBW_EMAIL=y\n")
	if _, err := Load(path); err == nil {
		t.Fatal("missing password accepted")
	}
}

func TestCacheRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "session.json")
	if err := SaveCache(path, "https://v", "e@x", "tok", time.Hour); err != nil {
		t.Fatal(err)
	}
	if tok, ok := LoadCache(path, "https://v", "e@x"); !ok || tok != "tok" {
		t.Fatalf("cache miss: %q %v", tok, ok)
	}
	if _, ok := LoadCache(path, "https://other", "e@x"); ok {
		t.Fatal("cache accepted for another server")
	}
	if err := ClearCache(path); err != nil {
		t.Fatal(err)
	}
	if _, ok := LoadCache(path, "https://v", "e@x"); ok {
		t.Fatal("cache survived clear")
	}
}

func TestCacheExpires(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	if err := SaveCache(path, "https://v", "e@x", "tok", -time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, ok := LoadCache(path, "https://v", "e@x"); ok {
		t.Fatal("expired cache accepted")
	}
}

func TestRedactor(t *testing.T) {
	r := &Redactor{}
	r.Add("s3cret-value")
	r.Add("ab")
	out := r.Clean("token=s3cret-value and ab")
	if strings.Contains(out, "s3cret-value") {
		t.Fatalf("secret survived: %q", out)
	}
	if !strings.Contains(out, "ab") {
		t.Fatalf("short value should not be redacted: %q", out)
	}
}
