package store

import (
	"errors"
	"testing"

	"github.com/noir017/vlt/internal/crypt"
	"github.com/noir017/vlt/internal/vw"
)

func testVault(t *testing.T) *Vault {
	t.Helper()
	key := crypt.Stretch([]byte("0123456789abcdef0123456789abcdef"))
	enc := func(s string) string {
		out, err := key.Encrypt([]byte(s))
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	folder, _ := key.Encrypt([]byte("agent"))
	sync := &vw.Sync{
		Profile: vw.Profile{ID: "user-1"},
		Folders: []vw.Folder{{ID: "f1", Name: folder}},
		Ciphers: []vw.Cipher{
			{ID: "c1", Raw: map[string]any{
				"type": float64(1), "name": enc("svc/gitea"), "folderId": "f1",
				"login": map[string]any{
					"username": enc("root"), "password": enc("pw-1"), "totp": nil,
					"uris": []any{map[string]any{"uri": "https://gitea.example.com"}},
				},
			}},
			{ID: "c2", Raw: map[string]any{
				"type": float64(1), "name": enc("api/newapi"),
				"login": map[string]any{
					"username": enc("svc"), "password": enc("pw-2"),
					"uris": []any{map[string]any{"uri": "https://llm.example.com"}},
				},
			}},
		},
	}
	v, err := New(sync, key)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestFindAndDecrypt(t *testing.T) {
	v := testVault(t)
	it, err := v.Find("svc/gitea")
	if err != nil {
		t.Fatal(err)
	}
	if it.Password != "pw-1" || it.Username != "root" || it.Folder != "agent" {
		t.Fatalf("unexpected item %+v", it)
	}
	if len(it.URIs) != 1 || it.URIs[0] != "https://gitea.example.com" {
		t.Fatalf("unexpected uris %v", it.URIs)
	}
}

func TestFindMissing(t *testing.T) {
	v := testVault(t)
	if _, err := v.Find("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestFindDuplicate(t *testing.T) {
	v := testVault(t)
	dup, err := v.Find("svc/gitea")
	if err != nil {
		t.Fatal(err)
	}
	v.Items = append(v.Items, dup)
	if _, err := v.Find("svc/gitea"); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("duplicate name not rejected: %v", err)
	}
}

func TestSearch(t *testing.T) {
	v := testVault(t)
	if got := len(v.Search("gitea")); got != 1 {
		t.Fatalf("search by name = %d", got)
	}
	if got := len(v.Search("example.com")); got != 2 {
		t.Fatalf("search by uri = %d", got)
	}
	if got := len(v.Search("root")); got != 1 {
		t.Fatalf("search by username = %d", got)
	}
	if got := len(v.Search("")); got != 2 {
		t.Fatalf("empty search = %d", got)
	}
}

func TestCloneRawIsDeep(t *testing.T) {
	raw := map[string]any{"login": map[string]any{"username": "x"}}
	cp, err := CloneRaw(raw)
	if err != nil {
		t.Fatal(err)
	}
	cp["login"].(map[string]any)["username"] = "y"
	if raw["login"].(map[string]any)["username"] != "x" {
		t.Fatal("clone shares nested maps")
	}
}

func TestFindByID(t *testing.T) {
	v := testVault(t)
	it, err := v.FindByID("c2")
	if err != nil {
		t.Fatal(err)
	}
	if it.Name != "api/newapi" {
		t.Fatalf("name = %q", it.Name)
	}
	if _, err := v.FindByID("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}
