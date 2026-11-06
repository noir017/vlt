// Package secret loads the account configuration and keeps the on-disk
// material as tight as the platform allows.
package secret

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Config is the small env file vlt reads.
type Config struct {
	Server   string
	Email    string
	Password string
	Path     string
}

// DefaultPath returns the first existing configuration file.
func DefaultPath() string {
	if p := os.Getenv("VLT_CONFIG"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	preferred := filepath.Join(home, ".secrets", "vlt.env")
	if _, err := os.Stat(preferred); err == nil {
		return preferred
	}
	// Compatibility with the file created when the account was registered.
	return filepath.Join(home, ".secrets", "vaultwarden-agent.env")
}

// Load reads path, checks permissions and returns the configuration.
func Load(path string) (*Config, error) {
	if path == "" {
		path = DefaultPath()
	}
	if path == "" {
		return nil, fmt.Errorf("cannot determine a configuration path")
	}
	if err := checkFile(path); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", path, err)
	}
	values := parse(string(data))
	cfg := &Config{
		Server:   values["BW_SERVER"],
		Email:    values["BW_EMAIL"],
		Password: values["BW_PASSWORD"],
		Path:     path,
	}
	if cfg.Password == "" && values["BW_PASSWORD_FILE"] != "" {
		p := values["BW_PASSWORD_FILE"]
		if err := checkFile(p); err != nil {
			return nil, err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("cannot read password file: %w", err)
		}
		cfg.Password = trimNewline(string(b))
	}
	for name, v := range map[string]string{"BW_SERVER": cfg.Server, "BW_EMAIL": cfg.Email, "BW_PASSWORD": cfg.Password} {
		if strings.TrimSpace(v) == "" {
			return nil, fmt.Errorf("%s is missing from %s", name, path)
		}
	}
	return cfg, nil
}

func parse(s string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if len(v) >= 2 {
			if (v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'') {
				v = v[1 : len(v)-1]
			}
		}
		out[k] = v
	}
	return out
}

func checkFile(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("cannot open %s: %w", path, err)
	}
	if fi.IsDir() {
		return fmt.Errorf("%s is a directory", path)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s is readable by group or others (mode %04o); run: chmod 600 %s",
			path, fi.Mode().Perm(), path)
	}
	if dir := filepath.Dir(path); dir != "." {
		if di, err := os.Stat(dir); err == nil && di.Mode().Perm()&0o007 != 0 {
			return fmt.Errorf("%s is world-accessible (mode %04o); run: chmod 700 %s",
				dir, di.Mode().Perm(), dir)
		}
	}
	return nil
}

func trimNewline(s string) string {
	s = strings.TrimSuffix(s, "\n")
	return strings.TrimSuffix(s, "\r")
}
