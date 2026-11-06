package main

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/noir017/vlt/internal/crypt"
	"github.com/noir017/vlt/internal/store"
	"github.com/noir017/vlt/internal/vw"
)

func testApp() *app {
	key := crypt.Stretch([]byte("0123456789abcdef0123456789abcdef"))
	return &app{cl: &vw.Client{Key: key}, vault: &store.Vault{Key: key, UID: "user-1"}}
}

// checkURI asserts one written URI is encrypted and carries a valid checksum.
func checkURI(t *testing.T, key *crypt.Key, m map[string]any, want string) {
	t.Helper()
	encURI, _ := m["uri"].(string)
	if !store.IsEncString(encURI) {
		t.Fatalf("uri not encrypted: %q", encURI)
	}
	if got, err := key.DecryptString(encURI); err != nil || got != want {
		t.Fatalf("uri decrypts to %q, %v; want %q", got, err, want)
	}
	sum := sha256.Sum256([]byte(want))
	encSum, _ := m["uriChecksum"].(string)
	if got, err := key.DecryptString(encSum); err != nil || got != base64.StdEncoding.EncodeToString(sum[:]) {
		t.Fatalf("uriChecksum = %q, %v", got, err)
	}
}

func TestNewItemEncryptsURIs(t *testing.T) {
	a := testApp()
	body, err := buildNewItem(a, "svc/x", "login", optString{}, []string{"https://a.example.com", "https://b.example.com"}, "pw", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	uris := body["login"].(map[string]any)["uris"].([]map[string]any)
	if len(uris) != 2 {
		t.Fatalf("uris = %d", len(uris))
	}
	checkURI(t, a.cl.Key, uris[0], "https://a.example.com")
	checkURI(t, a.cl.Key, uris[1], "https://b.example.com")
}

func TestUpdateReencryptsLegacyURIs(t *testing.T) {
	a := testApp()
	item := &store.Item{
		ID: "c1", URIs: []string{"https://legacy.example.com"},
		Raw: map[string]any{"type": float64(1), "login": map[string]any{
			"uri":  "https://legacy.example.com",
			"uris": []any{map[string]any{"uri": "https://legacy.example.com"}},
		}},
	}
	// only the password changes; the plaintext URI must still be re-encrypted
	body, err := buildUpdate(a, item, "svc/x", "login", optString{}, nil, "new-pw", "", "", false, true, false, "")
	if err != nil {
		t.Fatal(err)
	}
	login := body["login"].(map[string]any)
	if _, ok := login["uri"]; ok {
		t.Fatal("stale plaintext login.uri kept")
	}
	uris := login["uris"].([]map[string]any)
	if len(uris) != 1 {
		t.Fatalf("uris = %d", len(uris))
	}
	checkURI(t, a.cl.Key, uris[0], "https://legacy.example.com")
}
