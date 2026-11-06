package vw

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// Profile is the account block of a sync response.
type Profile struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Key   string `json:"key"`
}

// Folder is a folder with its still-encrypted name.
type Folder struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Cipher is a vault item kept as a raw object so unknown fields survive an
// update untouched.
type Cipher struct {
	ID  string
	Raw map[string]any
}

// Sync is the one-shot view of the vault used by every command.
type Sync struct {
	Profile Profile  `json:"profile"`
	Folders []Folder `json:"folders"`
	Ciphers []Cipher `json:"ciphers"`
}

// UnmarshalJSON adapts the ciphers array into raw maps.
func (s *Sync) UnmarshalJSON(data []byte) error {
	var wire struct {
		Profile Profile          `json:"profile"`
		Folders []Folder         `json:"folders"`
		Ciphers []map[string]any `json:"ciphers"`
		Data    []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	s.Profile = wire.Profile
	s.Folders = wire.Folders
	raw := wire.Ciphers
	if raw == nil {
		raw = wire.Data
	}
	s.Ciphers = make([]Cipher, 0, len(raw))
	for _, item := range raw {
		id, _ := item["id"].(string)
		s.Ciphers = append(s.Ciphers, Cipher{ID: id, Raw: item})
	}
	return nil
}

// Sync fetches profile, folders and ciphers in one request.
func (c *Client) Sync(ctx context.Context) (*Sync, error) {
	var out Sync
	if err := c.do(ctx, http.MethodGet, "/api/sync", nil, &out, true); err != nil {
		return nil, err
	}
	if out.Profile.ID == "" {
		return nil, fmt.Errorf("sync returned no profile")
	}
	c.UserID = out.Profile.ID
	return &out, nil
}

// Ciphers lists items only (used after the first sync when only items changed).
func (c *Client) Ciphers(ctx context.Context) ([]Cipher, error) {
	var wire struct {
		Data []map[string]any `json:"data"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/ciphers", nil, &wire, true); err != nil {
		return nil, err
	}
	out := make([]Cipher, 0, len(wire.Data))
	for _, item := range wire.Data {
		id, _ := item["id"].(string)
		out = append(out, Cipher{ID: id, Raw: item})
	}
	return out, nil
}

// CreateCipher posts a new item and returns the stored object.
func (c *Client) CreateCipher(ctx context.Context, body map[string]any) (*Cipher, error) {
	var out map[string]any
	if err := c.do(ctx, http.MethodPost, "/api/ciphers", body, &out, true); err != nil {
		return nil, err
	}
	id, _ := out["id"].(string)
	return &Cipher{ID: id, Raw: out}, nil
}

// UpdateCipher replaces an item.
func (c *Client) UpdateCipher(ctx context.Context, id string, body map[string]any) (*Cipher, error) {
	var out map[string]any
	if err := c.do(ctx, http.MethodPut, "/api/ciphers/"+id, body, &out, true); err != nil {
		return nil, err
	}
	return &Cipher{ID: id, Raw: out}, nil
}

// DeleteCipher removes an item.
func (c *Client) DeleteCipher(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/api/ciphers/"+id, nil, nil, true)
}

// CreateFolder creates a folder from an already-encrypted name.
func (c *Client) CreateFolder(ctx context.Context, encName string) (string, error) {
	var out struct {
		ID string `json:"id"`
	}
	if err := c.do(ctx, http.MethodPost, "/api/folders", map[string]string{"name": encName}, &out, true); err != nil {
		return "", err
	}
	return out.ID, nil
}

// ProfileInfo reads the account profile (used by doctor and by cached-token runs).
func (c *Client) ProfileInfo(ctx context.Context) (*Profile, error) {
	var out Profile
	if err := c.do(ctx, http.MethodGet, "/api/accounts/profile", nil, &out, true); err != nil {
		return nil, err
	}
	if out.ID != "" {
		c.UserID = out.ID
	}
	return &out, nil
}

// ServerConfig is the public configuration endpoint, used by doctor.
type ServerConfig struct {
	Version string `json:"version"`
	Server  struct {
		Name string `json:"name"`
	} `json:"server"`
}

// Config probes the server without authentication.
func (c *Client) Config(ctx context.Context) (*ServerConfig, error) {
	var out ServerConfig
	if err := c.do(ctx, http.MethodGet, "/api/config", nil, &out, false); err != nil {
		return nil, err
	}
	return &out, nil
}
