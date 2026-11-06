package vw

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/noir017/vlt/internal/crypt"
)

func TestLoginFlow(t *testing.T) {
	const (
		email    = "user@example.com"
		password = "correct horse battery staple"
	)
	params := crypt.KDFParams{Type: crypt.KDFPBKDF2SHA256, Iterations: 1000}
	master, err := crypt.DeriveMaster(password, email, params)
	if err != nil {
		t.Fatal(err)
	}
	userKey := make([]byte, 64)
	for i := range userKey {
		userKey[i] = byte(i)
	}
	encUserKey, err := crypt.Stretch(master).Encrypt(userKey)
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/identity/accounts/prelogin", func(w http.ResponseWriter, r *http.Request) {
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		if in["email"] != email {
			t.Errorf("prelogin email = %q", in["email"])
		}
		fmt.Fprintf(w, `{"Kdf":0,"KdfIterations":%d}`, params.Iterations)
	})
	mux.HandleFunc("/identity/connect/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if got := r.PostForm.Get("password"); got != crypt.HashMaster(master, password) {
			t.Errorf("password hash mismatch")
		}
		if r.PostForm.Get("grant_type") != "password" || r.PostForm.Get("client_id") != "cli" {
			t.Errorf("unexpected form %v", r.PostForm)
		}
		fmt.Fprintf(w, `{"access_token":"tok-123","expires_in":7200,"Key":%q}`, encUserKey)
	})
	mux.HandleFunc("/api/sync", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok-123" {
			t.Errorf("missing bearer token")
		}
		fmt.Fprintf(w, `{"profile":{"id":"user-1","email":%q,"key":%q},"folders":[],"ciphers":[]}`, email, encUserKey)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := New(srv.URL, email, "test")
	if err := c.Prelogin(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c.KDF.Iterations != params.Iterations {
		t.Fatalf("kdf = %+v", c.KDF)
	}
	if _, err := c.Login(context.Background(), password); err != nil {
		t.Fatal(err)
	}
	if c.Key == nil || len(c.Key.Enc) != 32 {
		t.Fatal("user key not derived")
	}
	sync, err := c.Sync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if sync.Profile.ID != "user-1" {
		t.Fatalf("profile = %+v", sync.Profile)
	}
}

func TestHTTPErrorMessage(t *testing.T) {
	cases := map[string]string{
		`{"message":"nope"}`:               "nope",
		`{"errorModel":{"message":"bad"}}`: "bad",
		`{"error":{"description":"gone"}}`: "gone",
		`<html>not a vault</html>`:         "unexpected HTML response (is the server URL correct?)",
		`plain`:                            "plain",
	}
	for body, want := range cases {
		if got := errorMessage([]byte(body)); got != want {
			t.Errorf("errorMessage(%q) = %q, want %q", body, got, want)
		}
	}
}

func TestDeviceIDIsStable(t *testing.T) {
	a := deviceID("user@example.com")
	if a != deviceID("user@example.com") {
		t.Fatal("device id is not stable")
	}
	if a == deviceID("other@example.com") {
		t.Fatal("device id collides")
	}
	if len(strings.Split(a, "-")) != 5 {
		t.Fatalf("unexpected shape %q", a)
	}
}
