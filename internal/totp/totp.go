// Package totp computes one-time codes for values stored in a vault item,
// either as an otpauth:// URI or as a bare base32 secret.
package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Config is a parsed TOTP definition.
type Config struct {
	Secret []byte
	Digits int
	Period int
	Algo   string
}

// Parse accepts otpauth://totp/...?secret=... or a bare base32 secret.
func Parse(raw string) (*Config, error) {
	raw = strings.TrimSpace(raw)
	cfg := &Config{Digits: 6, Period: 30, Algo: "SHA1"}
	secret := raw
	if strings.HasPrefix(strings.ToLower(raw), "otpauth://") {
		u, err := url.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid otpauth URI: %w", err)
		}
		if !strings.EqualFold(u.Host, "totp") {
			return nil, fmt.Errorf("unsupported otpauth type %q", u.Host)
		}
		q := u.Query()
		secret = q.Get("secret")
		if v := q.Get("digits"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n >= 6 && n <= 10 {
				cfg.Digits = n
			}
		}
		if v := q.Get("period"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				cfg.Period = n
			}
		}
		if v := q.Get("algorithm"); v != "" {
			cfg.Algo = strings.ToUpper(v)
		}
	}
	secret = strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(secret, " ", ""), "-", ""))
	secret = strings.TrimRight(secret, "=")
	if secret == "" {
		return nil, fmt.Errorf("no TOTP secret found")
	}
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		return nil, fmt.Errorf("invalid TOTP secret: %w", err)
	}
	cfg.Secret = decoded
	if cfg.Algo != "SHA1" && cfg.Algo != "SHA256" && cfg.Algo != "SHA512" {
		return nil, fmt.Errorf("unsupported TOTP algorithm %q", cfg.Algo)
	}
	return cfg, nil
}

// Code returns the code for t.
func (c *Config) Code(t time.Time) string {
	counter := uint64(t.Unix() / int64(c.Period))
	return c.code(counter)
}

func (c *Config) code(counter uint64) string {
	var hf func() hash.Hash
	switch c.Algo {
	case "SHA256":
		hf = sha256.New
	case "SHA512":
		hf = sha512.New
	default:
		hf = sha1.New
	}
	buf := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		buf[i] = byte(counter)
		counter >>= 8
	}
	mac := hmac.New(hf, c.Secret)
	mac.Write(buf)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])
	mod := uint32(1)
	for i := 0; i < c.Digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", c.Digits, value%mod)
}
