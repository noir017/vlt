package main

import (
	"strings"
	"testing"
)

func TestSplitRef(t *testing.T) {
	cases := []struct {
		in          string
		name, field string
		ok          bool
	}{
		{"svc/gitea.password", "svc/gitea", "password", true},
		{"svc/gitea", "svc/gitea", "password", true},
		{"api/x.totp", "api/x", "totp", true},
		{"a.b.c", "a.b", "c", true},
		{".password", "", "", false},
		{"name.", "", "", false},
		{"", "", "", false},
	}
	for _, c := range cases {
		name, field, ok := splitRef(c.in)
		if name != c.name || field != c.field || ok != c.ok {
			t.Errorf("splitRef(%q) = (%q,%q,%v), want (%q,%q,%v)", c.in, name, field, ok, c.name, c.field, c.ok)
		}
	}
}

func TestGeneratePassword(t *testing.T) {
	pw, err := generatePassword(32)
	if err != nil {
		t.Fatal(err)
	}
	if len(pw) != 32 {
		t.Fatalf("length = %d", len(pw))
	}
	for _, r := range pw {
		if !strings.ContainsRune("abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789", r) {
			t.Fatalf("unexpected character %q in %q", r, pw)
		}
	}
	if _, err := generatePassword(8); err == nil {
		t.Fatal("short length accepted")
	}
}

func TestTrimNewline(t *testing.T) {
	for in, want := range map[string]string{
		"abc\n":   "abc",
		"abc\r\n": "abc",
		"abc":     "abc",
		"abc\n\n": "abc\n",
		"":        "",
	} {
		if got := trimNewline(in); got != want {
			t.Errorf("trimNewline(%q) = %q, want %q", in, got, want)
		}
	}
}
