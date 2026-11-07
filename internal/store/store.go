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

// CustomField is one decrypted custom field on a vault entry.
type CustomField struct {
	Type  int // 0 = text, 1 = hidden, 2 = boolean, 3 = linked
	Name  string
	Value string
}

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
	Fields    []CustomField
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
	// Items created by current Bitwarden clients carry their own wrapped key;
	// fields are encrypted with it, not with the account key.
	fieldKey := key
	if wrapped, _ := c.Raw["key"].(string); wrapped != "" {
		ik, err := key.UnwrapItemKey(wrapped)
		if err != nil {
			return nil, fmt.Errorf("cannot decrypt item %s: %w", c.ID, err)
		}
		fieldKey = ik
	}
	name, err := decField(fieldKey, c.Raw["name"])
	if err != nil {
		return nil, fmt.Errorf("cannot decrypt item %s: %w", c.ID, err)
	}
	it.Name = name
	it.Notes, _ = decField(fieldKey, c.Raw["notes"])
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
		it.Username, _ = decField(fieldKey, login["username"])
		it.Password, _ = decField(fieldKey, login["password"])
		it.TOTP, _ = decField(fieldKey, login["totp"])
		if uris, ok := login["uris"].([]any); ok {
			for _, u := range uris {
				if m, ok := u.(map[string]any); ok {
					if s, ok := decURI(fieldKey, m["uri"]); ok {
						it.URIs = append(it.URIs, s)
					}
				}
			}
		}
	}
	if rawFields, ok := c.Raw["fields"].([]any); ok {
		for _, rf := range rawFields {
			if m, ok := rf.(map[string]any); ok {
				fType := 0
				if t, ok := m["type"].(float64); ok {
					fType = int(t)
				}
				fName, _ := decField(fieldKey, m["name"])
				fVal, _ := decField(fieldKey, m["value"])
				it.Fields = append(it.Fields, CustomField{
					Type:  fType,
					Name:  fName,
					Value: fVal,
				})
			}
		}
	}
	return it, nil
}

// decURI reads one login URI. vlt up to 0.5.0 stored URIs in plaintext, so a
// value that is not an EncString is taken as-is; an EncString that fails to
// decrypt is dropped rather than shown as ciphertext.
func decURI(key *crypt.Key, raw any) (string, bool) {
	s, ok := raw.(string)
	if !ok || s == "" {
		return "", false
	}
	if !IsEncString(s) {
		return s, true
	}
	plain, err := key.DecryptString(s)
	if err != nil {
		return "", false
	}
	return plain, true
}

// IsEncString reports whether s looks like a type-2 Bitwarden EncString.
func IsEncString(s string) bool {
	return strings.HasPrefix(s, "2.") && strings.Count(s, "|") == 2
}

// HasPlainURI reports whether a raw login carries a URI stored in plaintext.
func HasPlainURI(login map[string]any) bool {
	uris, _ := login["uris"].([]any)
	for _, u := range uris {
		if m, ok := u.(map[string]any); ok {
			if s, ok := m["uri"].(string); ok && s != "" && !IsEncString(s) {
				return true
			}
		}
	}
	return false
}

func decField(key *crypt.Key, raw any) (string, error) {
	s, ok := raw.(string)
	if !ok || s == "" {
		return "", nil
	}
	return key.DecryptString(s)
}

// GetField returns a custom field by name (case-insensitive).
func (it *Item) GetField(name string) (CustomField, bool) {
	for _, f := range it.Fields {
		if strings.EqualFold(f.Name, name) {
			return f, true
		}
	}
	return CustomField{}, false
}

// HasSecret reports whether the item carries anything that must be masked.
func (it *Item) HasSecret() bool {
	if it.Password != "" || it.Notes != "" || it.TOTP != "" {
		return true
	}
	for _, f := range it.Fields {
		if f.Type == 1 && f.Value != "" {
			return true
		}
	}
	return false
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
			strings.Contains(strings.ToLower(strings.Join(it.URIs, " ")), q) ||
			matchCustomFields(it.Fields, q) {
			out = append(out, it)
		}
	}
	return out
}

func matchCustomFields(fields []CustomField, q string) bool {
	for _, f := range fields {
		if strings.Contains(strings.ToLower(f.Name), q) ||
			strings.Contains(strings.ToLower(f.Value), q) {
			return true
		}
	}
	return false
}

// FolderInfo represents a decrypted folder with its item count.
type FolderInfo struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Count int    `json:"item_count"`
}

// ListFolders returns all decrypted folders sorted by name with their active item counts.
func (v *Vault) ListFolders() []FolderInfo {
	counts := make(map[string]int)
	for _, it := range v.Items {
		if !it.Deleted && it.FolderID != "" {
			counts[it.FolderID]++
		}
	}
	out := make([]FolderInfo, 0, len(v.folderNames))
	for id, name := range v.folderNames {
		out = append(out, FolderInfo{
			ID:    id,
			Name:  name,
			Count: counts[id],
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})
	return out
}

// FolderByName returns the folder matching name (exact match).
func (v *Vault) FolderByName(name string) (FolderInfo, bool) {
	for _, f := range v.ListFolders() {
		if f.Name == name {
			return f, true
		}
	}
	return FolderInfo{}, false
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
