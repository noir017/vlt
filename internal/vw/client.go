// Package vw is a minimal Vaultwarden/Bitwarden REST client: prelogin, login,
// sync and cipher CRUD. It holds no policy; callers decide what to print.
package vw

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/noir017/vlt/internal/crypt"
)

// Client talks to one Vaultwarden account.
type Client struct {
	Base      string
	Email     string
	HTTP      *http.Client
	Token     string
	UserID    string
	Key       *crypt.Key
	KDF       crypt.KDFParams
	UserAgent string
}

// New builds a client for base (e.g. https://vault.example.com).
func New(base, email, version string) *Client {
	return &Client{
		Base:      strings.TrimRight(base, "/"),
		Email:     crypt.NormalizeEmail(email),
		HTTP:      &http.Client{Timeout: 20 * time.Second},
		UserAgent: "vlt/" + version,
	}
}

type preloginResponse struct {
	Kdf           int `json:"Kdf"`
	KdfIterations int `json:"KdfIterations"`
	KdfMemory     int `json:"KdfMemory"`
	KdfParallel   int `json:"KdfParallelism"`
}

// Prelogin fetches the KDF parameters for the account.
func (c *Client) Prelogin(ctx context.Context) error {
	var out preloginResponse
	if err := c.do(ctx, http.MethodPost, "/identity/accounts/prelogin",
		map[string]string{"email": c.Email}, &out, false); err != nil {
		return err
	}
	c.KDF = crypt.KDFParams{
		Type:        out.Kdf,
		Iterations:  out.KdfIterations,
		Memory:      out.KdfMemory,
		Parallelism: out.KdfParallel,
	}
	return nil
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	Key         string `json:"Key"`
}

// Login exchanges the master password for an access token and stores the
// decrypted user key. It returns the token lifetime.
func (c *Client) Login(ctx context.Context, password string) (time.Duration, error) {
	master, err := crypt.DeriveMaster(password, c.Email, c.KDF)
	if err != nil {
		return 0, err
	}
	form := url.Values{
		"grant_type":       {"password"},
		"username":         {c.Email},
		"password":         {crypt.HashMaster(master, password)},
		"scope":            {"api offline_access"},
		"client_id":        {"cli"},
		"deviceType":       {"8"},
		"deviceIdentifier": {deviceID(c.Email)},
		"deviceName":       {"vlt"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Base+"/identity/connect/token",
		strings.NewReader(form.Encode()))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.UserAgent)

	var out tokenResponse
	if err := c.send(req, &out); err != nil {
		if isRateLimited(err) {
			select {
			case <-time.After(1500 * time.Millisecond):
			case <-ctx.Done():
				return 0, ctx.Err()
			}
			if err := c.retry(req, &out); err != nil {
				return 0, err
			}
		} else {
			return 0, err
		}
	}
	if out.AccessToken == "" {
		return 0, fmt.Errorf("login returned no token")
	}
	c.Token = out.AccessToken
	if err := c.Unlock(out.Key, master); err != nil {
		return 0, err
	}
	ttl := time.Duration(out.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = 2 * time.Hour
	}
	return ttl, nil
}

// Unlock decrypts the server-side user key with an already-derived master key.
func (c *Client) Unlock(encUserKey string, masterKey []byte) error {
	if encUserKey == "" {
		return fmt.Errorf("server returned no user key")
	}
	plain, err := crypt.Stretch(masterKey).Decrypt(encUserKey)
	if err != nil {
		return fmt.Errorf("cannot decrypt user key: %w", err)
	}
	if len(plain) != 64 {
		return fmt.Errorf("unexpected user key length %d", len(plain))
	}
	c.Key = &crypt.Key{Enc: plain[:32], Mac: plain[32:]}
	return nil
}

// UnlockWithPassword derives the master key and decrypts the user key.
func (c *Client) UnlockWithPassword(encUserKey, password string) error {
	master, err := crypt.DeriveMaster(password, c.Email, c.KDF)
	if err != nil {
		return err
	}
	return c.Unlock(encUserKey, master)
}

// EnsureToken uses the cached token if it is still accepted, otherwise logs in.
// It returns true when a fresh login happened.
func (c *Client) EnsureToken(ctx context.Context, password, cached string) (bool, error) {
	if cached != "" {
		c.Token = cached
		return false, nil
	}
	_, err := c.Login(ctx, password)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (c *Client) do(ctx context.Context, method, path string, body, out any, auth bool) error {
	var raw []byte
	if body != nil {
		var err error
		raw, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Base+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.UserAgent)
	if auth && c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	return c.send(req, out)
}

func (c *Client) send(req *http.Request, out any) error {
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return &NetError{Err: err}
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode >= 300 {
		return &HTTPError{Status: resp.StatusCode, Message: errorMessage(data)}
	}
	if out == nil || len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("cannot decode server response: %w", err)
	}
	return nil
}

func (c *Client) retry(req *http.Request, out any) error {
	// The body was consumed by the first attempt; rebuild it.
	if req.GetBody != nil {
		body, err := req.GetBody()
		if err != nil {
			return err
		}
		req.Body = body
	}
	return c.send(req, out)
}

// HTTPError is a non-2xx response.
type HTTPError struct {
	Status  int
	Message string
}

func (e *HTTPError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("server returned HTTP %d", e.Status)
	}
	return fmt.Sprintf("server returned HTTP %d: %s", e.Status, e.Message)
}

// NetError is a transport failure.
type NetError struct{ Err error }

func (e *NetError) Error() string { return "cannot reach server: " + e.Err.Error() }

func (e *NetError) Unwrap() error { return e.Err }

func isRateLimited(err error) bool {
	he, ok := err.(*HTTPError)
	return ok && he.Status == http.StatusTooManyRequests
}

func errorMessage(body []byte) string {
	var env struct {
		Message    string `json:"message"`
		ErrorModel struct {
			Message string `json:"message"`
		} `json:"errorModel"`
		Error struct {
			Description string `json:"description"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &env) == nil {
		for _, m := range []string{env.ErrorModel.Message, env.Message, env.Error.Description} {
			if m != "" {
				return m
			}
		}
	}
	if len(body) > 0 && body[0] == '<' {
		return "unexpected HTML response (is the server URL correct?)"
	}
	return strings.TrimSpace(string(body))
}

// deviceID derives a stable device identifier from the account email so the
// server sees one device instead of a new one on every call.
func deviceID(email string) string {
	sum := sha256.Sum256([]byte(email))
	return fmt.Sprintf("%x-%x-%x-%x-%x", sum[0:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16])
}
