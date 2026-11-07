package main

import (
	"testing"

	"github.com/noir017/vlt/internal/store"
	"github.com/noir017/vlt/internal/vw"
)

func TestParseCustomFieldArgs(t *testing.T) {
	text := []string{"alias_1=user1@139.com", "del_me="}
	hidden := []string{"pin=1234"}
	parsed, err := parseCustomFieldArgs(text, hidden)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed) != 3 {
		t.Fatalf("len = %d", len(parsed))
	}
	if parsed[0].Name != "alias_1" || parsed[0].Value != "user1@139.com" || parsed[0].Type != 0 {
		t.Errorf("parsed[0] = %+v", parsed[0])
	}
	if parsed[1].Name != "del_me" || parsed[1].Value != "" || parsed[1].Type != 0 {
		t.Errorf("parsed[1] = %+v", parsed[1])
	}
	if parsed[2].Name != "pin" || parsed[2].Value != "1234" || parsed[2].Type != 1 {
		t.Errorf("parsed[2] = %+v", parsed[2])
	}

	if _, err := parseCustomFieldArgs([]string{"invalid"}, nil); err == nil {
		t.Fatal("invalid field without '=' was accepted")
	}
	if _, err := parseCustomFieldArgs([]string{" =value"}, nil); err == nil {
		t.Fatal("field with empty name was accepted")
	}
}

func TestNewItemWithCustomFields(t *testing.T) {
	a := testApp()
	fields := []customFieldArg{
		{Type: 0, Name: "alias_1", Value: "one@139.com"},
		{Type: 1, Name: "secret_token", Value: "sec123"},
	}
	body, err := buildNewItem(a, "mail/139", "login", optString{}, nil, "pw", "", "", "", fields)
	if err != nil {
		t.Fatal(err)
	}
	rawFields, ok := body["fields"].([]any)
	if !ok || len(rawFields) != 2 {
		t.Fatalf("fields = %v", body["fields"])
	}
	itemKey := bodyKey(t, a, body)

	// Decrypt through store.New
	sync := &vw.Sync{
		Profile: vw.Profile{ID: "user-1"},
		Ciphers: []vw.Cipher{{ID: "c1", Raw: body}},
	}
	v, err := store.New(sync, a.cl.Key)
	if err != nil {
		t.Fatal(err)
	}
	it, err := v.Find("mail/139")
	if err != nil {
		t.Fatal(err)
	}
	if len(it.Fields) != 2 {
		t.Fatalf("it.Fields len = %d", len(it.Fields))
	}
	f1, ok := it.GetField("alias_1")
	if !ok || f1.Value != "one@139.com" || f1.Type != 0 {
		t.Errorf("f1 = %+v", f1)
	}
	f2, ok := it.GetField("secret_token")
	if !ok || f2.Value != "sec123" || f2.Type != 1 {
		t.Errorf("f2 = %+v", f2)
	}

	// itemField helper
	val1, err := itemField(it, "alias_1")
	if err != nil || val1 != "one@139.com" {
		t.Errorf("itemField(alias_1) = %q, %v", val1, err)
	}
	val2, err := itemField(it, "secret_token")
	if err != nil || val2 != "sec123" {
		t.Errorf("itemField(secret_token) = %q, %v", val2, err)
	}

	// Secret masking
	if isSecretField("alias_1", it) {
		t.Error("text field alias_1 reported as secret")
	}
	if !isSecretField("secret_token", it) {
		t.Error("hidden field secret_token not reported as secret")
	}
	_ = itemKey
}

func TestUpdateCustomFields(t *testing.T) {
	a := testApp()
	initialFields := []customFieldArg{
		{Type: 0, Name: "alias_1", Value: "old@139.com"},
		{Type: 0, Name: "to_delete", Value: "bye"},
	}
	body, err := buildNewItem(a, "mail/139", "login", optString{}, nil, "pw", "", "", "", initialFields)
	if err != nil {
		t.Fatal(err)
	}

	sync := &vw.Sync{Profile: vw.Profile{ID: "user-1"}, Ciphers: []vw.Cipher{{ID: "c1", Raw: body}}}
	v, err := store.New(sync, a.cl.Key)
	if err != nil {
		t.Fatal(err)
	}
	it, _ := v.Find("mail/139")

	updateFields := []customFieldArg{
		{Type: 0, Name: "alias_1", Value: "new@139.com"}, // update
		{Type: 0, Name: "to_delete", Value: ""},          // delete
		{Type: 0, Name: "alias_2", Value: "two@139.com"}, // add
	}
	upd, err := buildUpdate(a, it, "mail/139", "login", optString{}, nil, "", "", "", false, false, false, "", updateFields)
	if err != nil {
		t.Fatal(err)
	}

	sync2 := &vw.Sync{Profile: vw.Profile{ID: "user-1"}, Ciphers: []vw.Cipher{{ID: "c1", Raw: upd}}}
	v2, err := store.New(sync2, a.cl.Key)
	if err != nil {
		t.Fatal(err)
	}
	it2, _ := v2.Find("mail/139")

	if len(it2.Fields) != 2 {
		t.Fatalf("updated fields len = %d, want 2 (%+v)", len(it2.Fields), it2.Fields)
	}
	if f, ok := it2.GetField("alias_1"); !ok || f.Value != "new@139.com" {
		t.Errorf("alias_1 = %+v", f)
	}
	if f, ok := it2.GetField("alias_2"); !ok || f.Value != "two@139.com" {
		t.Errorf("alias_2 = %+v", f)
	}
	if _, ok := it2.GetField("to_delete"); ok {
		t.Error("to_delete was not deleted")
	}
}
