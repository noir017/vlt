package main

import (
	"testing"

	"github.com/noir017/vlt/internal/store"
)

func TestNewItemCarriesItemKey(t *testing.T) {
	a := testApp()
	body, err := buildNewItem(a, "svc/x", "login", optString{}, nil, "pw", "note", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	itemKey := bodyKey(t, a, body)
	if got, err := itemKey.DecryptString(body["name"].(string)); err != nil || got != "svc/x" {
		t.Fatalf("name decrypts to %q, %v", got, err)
	}
	if _, err := a.cl.Key.DecryptString(body["name"].(string)); err == nil {
		t.Fatal("field is still readable with the account key")
	}
}

func TestUpdateKeepsExistingItemKey(t *testing.T) {
	a := testApp()
	body, err := buildNewItem(a, "svc/x", "login", optString{}, []string{"https://x.example.com"}, "old", "", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	itemKey := bodyKey(t, a, body)
	item := &store.Item{ID: "c1", Raw: body}
	upd, err := buildUpdate(a, item, "svc/x", "login", optString{}, nil, "new", "", "", false, true, false, "", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if upd["key"] != body["key"] {
		t.Fatal("update replaced the wrapped item key")
	}
	login := upd["login"].(map[string]any)
	if got, err := itemKey.DecryptString(login["password"].(string)); err != nil || got != "new" {
		t.Fatalf("password decrypts to %q, %v", got, err)
	}
}

func TestUpdateMigratesLegacyItem(t *testing.T) {
	a := testApp()
	item := &store.Item{ID: "c1", Raw: map[string]any{
		"type": float64(1), "name": mustEnc(t, a, "svc/old"),
		"login": map[string]any{"username": mustEnc(t, a, "root")},
	}}
	upd, err := buildUpdate(a, item, "svc/old", "login", optString{}, nil, "", "", "", false, false, false, "", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if upd["key"] == nil || upd["key"] == "" {
		t.Fatal("legacy item was not given a wrapped key")
	}
	itemKey := bodyKey(t, a, upd)
	if got, err := itemKey.DecryptString(upd["name"].(string)); err != nil || got != "svc/old" {
		t.Fatalf("name decrypts to %q, %v", got, err)
	}
	login := upd["login"].(map[string]any)
	if got, err := itemKey.DecryptString(login["username"].(string)); err != nil || got != "root" {
		t.Fatalf("untouched username decrypts to %q, %v", got, err)
	}
}

func mustEnc(t *testing.T, a *app, s string) string {
	t.Helper()
	out, err := a.cl.Key.Encrypt([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return out
}
