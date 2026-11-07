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

func TestEncryptedAndLegacyURIs(t *testing.T) {
	key := crypt.Stretch([]byte("0123456789abcdef0123456789abcdef"))
	enc := func(s string) string {
		out, err := key.Encrypt([]byte(s))
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	sync := &vw.Sync{Ciphers: []vw.Cipher{{ID: "c1", Raw: map[string]any{
		"type": float64(1), "name": enc("svc/x"),
		"login": map[string]any{"uris": []any{
			map[string]any{"uri": enc("https://new.example.com")},
			map[string]any{"uri": "https://legacy.example.com"},
			map[string]any{"uri": "2.bm90|aXQ=|YmFk"}, // undecryptable: dropped
		}},
	}}}}
	v, err := New(sync, key)
	if err != nil {
		t.Fatal(err)
	}
	got := v.Items[0].URIs
	if len(got) != 2 || got[0] != "https://new.example.com" || got[1] != "https://legacy.example.com" {
		t.Fatalf("uris = %v", got)
	}
	if !HasPlainURI(v.Items[0].Raw["login"].(map[string]any)) {
		t.Fatal("legacy plaintext uri not detected")
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

func TestTrashFiltering(t *testing.T) {
	v := testVault(t)
	it, err := v.Find("svc/gitea")
	if err != nil {
		t.Fatal(err)
	}
	it.Deleted = true
	it.Raw["deletedDate"] = "2026-11-06T07:27:42.107188Z"

	if _, err := v.Find("svc/gitea"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("trashed item still visible: %v", err)
	}
	if _, err := v.FindTrashed("svc/gitea"); err != nil {
		t.Fatalf("FindTrashed: %v", err)
	}
	if _, err := v.FindByID(it.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("FindByID returned a trashed item")
	}
	if _, err := v.FindTrashedByID(it.ID); err != nil {
		t.Fatalf("FindTrashedByID: %v", err)
	}
	if len(v.Trashed()) != 1 {
		t.Fatalf("Trashed = %d", len(v.Trashed()))
	}
	for _, got := range v.Search("gitea") {
		if got.ID == it.ID {
			t.Fatal("Search returned a trashed item")
		}
	}
}

func TestDecryptItemWithItemKey(t *testing.T) {
	account := crypt.Stretch([]byte("0123456789abcdef0123456789abcdef"))
	itemKey, err := crypt.NewItemKey()
	if err != nil {
		t.Fatal(err)
	}
	enc := func(s string) string {
		out, err := itemKey.Encrypt([]byte(s))
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	wrapped, err := account.WrapItemKey(itemKey)
	if err != nil {
		t.Fatal(err)
	}
	sync := &vw.Sync{
		Profile: vw.Profile{ID: "user-1"},
		Ciphers: []vw.Cipher{{ID: "c1", Raw: map[string]any{
			"type": float64(1), "name": enc("mail/163"), "key": wrapped,
			"login": map[string]any{
				"username": enc("u@163.com"), "password": enc("pw"),
				"uris": []any{map[string]any{"uri": enc("https://mail.163.com/")}},
			},
		}}},
	}
	v, err := New(sync, account)
	if err != nil {
		t.Fatal(err)
	}
	it, err := v.Find("mail/163")
	if err != nil {
		t.Fatal(err)
	}
	if it.Password != "pw" || it.Username != "u@163.com" || len(it.URIs) != 1 || it.URIs[0] != "https://mail.163.com/" {
		t.Fatalf("unexpected item %+v", it)
	}
}

func TestDecryptAndSearchCustomFields(t *testing.T) {
	key := crypt.Stretch([]byte("0123456789abcdef0123456789abcdef"))
	enc := func(s string) string {
		out, err := key.Encrypt([]byte(s))
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	sync := &vw.Sync{Ciphers: []vw.Cipher{{ID: "c1", Raw: map[string]any{
		"type": float64(1), "name": enc("mail/139"),
		"fields": []any{
			map[string]any{"type": float64(0), "name": enc("alias_1"), "value": enc("alias1@139.com")},
			map[string]any{"type": float64(1), "name": enc("secret_pin"), "value": enc("1234")},
		},
	}}}}
	v, err := New(sync, key)
	if err != nil {
		t.Fatal(err)
	}
	it, err := v.Find("mail/139")
	if err != nil {
		t.Fatal(err)
	}
	if len(it.Fields) != 2 {
		t.Fatalf("fields = %d", len(it.Fields))
	}
	f1, ok := it.GetField("alias_1")
	if !ok || f1.Value != "alias1@139.com" || f1.Type != 0 {
		t.Fatalf("alias_1 = %+v", f1)
	}
	f2, ok := it.GetField("SECRET_PIN")
	if !ok || f2.Value != "1234" || f2.Type != 1 {
		t.Fatalf("secret_pin = %+v", f2)
	}
	if !it.HasSecret() {
		t.Fatal("item with hidden custom field should have HasSecret == true")
	}
	if got := len(v.Search("alias1@139.com")); got != 1 {
		t.Fatalf("search by custom field value = %d", got)
	}
}
