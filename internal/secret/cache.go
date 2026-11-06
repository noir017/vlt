package secret

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// CachePath is where the short-lived access token lives.
func CachePath() string {
	if p := os.Getenv("VLT_CACHE"); p != "" {
		return p
	}
	dir, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "vlt", "session.json")
}

// Cache is a bearer token for one server/account pair.
type Cache struct {
	Server    string    `json:"server"`
	Email     string    `json:"email"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// LoadCache returns the cached token when it is present, for this account and
// not expired.
func LoadCache(path, server, email string) (string, bool) {
	if path == "" {
		return "", false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	var c Cache
	if json.Unmarshal(data, &c) != nil {
		return "", false
	}
	if c.Server != server || c.Email != email || c.Token == "" || time.Now().After(c.ExpiresAt) {
		return "", false
	}
	return c.Token, true
}

// SaveCache writes the token with 0600 permissions.
func SaveCache(path, server, email, token string, ttl time.Duration) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	// Keep a very short window: the token is a bearer credential.
	if ttl > 15*time.Minute {
		ttl = 15 * time.Minute
	}
	c := Cache{Server: server, Email: email, Token: token, ExpiresAt: time.Now().Add(ttl)}
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ClearCache removes the token file.
func ClearCache(path string) error {
	if path == "" {
		return nil
	}
	err := os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
