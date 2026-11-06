// Package store turns the encrypted sync response into a searchable view.
package store

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/noir017/vlt/internal/crypt"
	"github.com/noir017/vlt/internal/vw"
)

// Item is one decrypted vault entry.
type Item struct {
	ID        string
	Type      int
	Name      string
	Username  string
	Password  string
	TOTP      string
	Notes     string
	URIs      []string
	FolderID  string
	Folder    string
	Updated   time.Time
	Deleted   bool
	DeletedAt time.Time
	Raw       map[string]any
}

// Vault is the decrypted view of one sync response.
type Vault struct {
	Key     *crypt.Key
	UID     string
	Folders []vw.Folder
	Items   []*Item

	folderNames map[string]string
}

// New decrypts every folder and item. A single undecryptable item fails the
// whole load: a partial view would hide a key mismatch.
func New(sync *vw.Sync, key *crypt.Key) (*Vault, error) {
	v := &Vault{Key: key, UID: sync.Profile.ID, Folders: sync.Folders, folderNames: map[string]string{}}
	for _, f := range sync.Folders {
		name, err := key.DecryptString(f.Name)
		if err != nil {
			return nil, fmt.Errorf("cannot decrypt folder %s: %w", f.ID, err)
		}
		v.folderNames[f.ID] = name
	}
	for _, c := range sync.Ciphers {
		item, err := decryptItem(c, key)
		if err != nil {
			return nil, err
		}
		item.Folder = v.folderNames[item.FolderID]
		v.Items = append(v.Items, item)
	}
	sort.Slice(v.Items, func(i, j int) bool { return v.Items[i].Name < v.Items[j].Name })
	return v, nil
}

func decryptItem(c vw.Cipher, key *crypt.Key) (*Item, error) {
	it := &Item{ID: c.ID, Raw: c.Raw}
	if n, ok := c.Raw["type"].(float64); ok {
		it.Type = int(n)
	}
	name, err := decField(key, c.Raw["name"])
	if err != nil {
		return nil, fmt.Errorf("cannot decrypt item %s: %w", c.ID, err)
	}
	it.Name = name
	it.Notes, _ = decField(key, c.Raw["notes"])
	if fid, ok := c.Raw["folderId"].(string); ok {
		it.FolderID = fid
	}
	if rd, ok := c.Raw["revisionDate"].(string); ok {
		if t, err := time.Parse(time.RFC3339Nano, rd); err == nil {
			it.Updated = t
		}
	}
	if dd, ok := c.Raw["deletedDate"].(string); ok && dd != "" {
		it.Deleted = true
		if t, err := time.Parse(time.RFC3339Nano, dd); err == nil {
			it.DeletedAt = t
		}
	}
	if login, ok := c.Raw["login"].(map[string]any); ok {
		it.Username, _ = decField(key, login["username"])
		it.Password, _ = decField(key, login["password"])
		it.TOTP, _ = decField(key, login["totp"])
		if uris, ok := login["uris"].([]any); ok {
			for _, u := range uris {
				if m, ok := u.(map[string]any); ok {
					if s, ok := m["uri"].(string); ok {
						it.URIs = append(it.URIs, s)
					}
				}
			}
		}
	}
	return it, nil
}

func decField(key *crypt.Key, raw any) (string, error) {
	s, ok := raw.(string)
	if !ok || s == "" {
		return "", nil
	}
	return key.DecryptString(s)
}

// HasSecret reports whether the item carries anything that must be masked.
func (it *Item) HasSecret() bool {
	return it.Password != "" || it.Notes != "" || it.TOTP != ""
}

// Find returns the single live item with this exact name.
func (v *Vault) Find(name string) (*Item, error) { return v.findByName(name, false) }

// FindTrashed returns the single trashed item with this exact name.
func (v *Vault) FindTrashed(name string) (*Item, error) { return v.findByName(name, true) }

func (v *Vault) findByName(name string, trashed bool) (*Item, error) {
	var hits []*Item
	for _, it := range v.Items {
		if it.Name == name && it.Deleted == trashed {
			hits = append(hits, it)
		}
	}
	switch len(hits) {
	case 0:
		return nil, ErrNotFound
	case 1:
		return hits[0], nil
	default:
		var ids []string
		for _, h := range hits {
			ids = append(ids, h.ID)
		}
		return nil, fmt.Errorf("name %q matches %d items (%s); rename the duplicates first",
			name, len(hits), strings.Join(ids, ", "))
	}
}

// FindByID returns the live item with this server-side id.
func (v *Vault) FindByID(id string) (*Item, error) { return v.findByID(id, false) }

// FindTrashedByID returns the trashed item with this id.
func (v *Vault) FindTrashedByID(id string) (*Item, error) { return v.findByID(id, true) }

func (v *Vault) findByID(id string, trashed bool) (*Item, error) {
	for _, it := range v.Items {
		if it.ID == id && it.Deleted == trashed {
			return it, nil
		}
	}
	return nil, ErrNotFound
}

// Trashed lists items in the trash.
func (v *Vault) Trashed() []*Item {
	var out []*Item
	for _, it := range v.Items {
		if it.Deleted {
			out = append(out, it)
		}
	}
	return out
}

// Search returns items whose name, username or URI contains query.
func (v *Vault) Search(query string) []*Item {
	q := strings.ToLower(query)
	var out []*Item
	for _, it := range v.Items {
		if it.Deleted {
			continue
		}
		if q == "" || strings.Contains(strings.ToLower(it.Name), q) ||
			strings.Contains(strings.ToLower(it.Username), q) ||
			strings.Contains(strings.ToLower(strings.Join(it.URIs, " ")), q) {
			out = append(out, it)
		}
	}
	return out
}

// FolderID resolves a folder name, creating it when missing.
func (v *Vault) FolderID(name string) (string, bool) {
	for id, n := range v.folderNames {
		if n == name {
			return id, false
		}
	}
	return "", true
}

// ErrNotFound marks a missing item.
var ErrNotFound = fmt.Errorf("not found")

// CloneRaw deep-copies the raw object before a patch.
func CloneRaw(raw map[string]any) (map[string]any, error) {
	b, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}
