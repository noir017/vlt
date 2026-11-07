package main

import (
	"testing"

	"github.com/noir017/vlt/internal/store"
)

func TestInferFolder(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"api/siyuan", "api"},
		{"id/github-139", "id"},
		{"mail/163.com", "mail"},
		{"svc/internal/redis", "svc"},
		{"standalone", ""},
		{"/root", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := inferFolder(c.in); got != c.want {
			t.Errorf("inferFolder(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestBuildUpdateFolderHandling(t *testing.T) {
	a := testApp()
	item := &store.Item{
		ID:       "c1",
		FolderID: "folder-1",
		Raw: map[string]any{
			"type":     float64(1),
			"name":     mustEnc(t, a, "api/test"),
			"folderId": "folder-1",
		},
	}

	// 1. folder not set -> folderId preserved
	upd1, err := buildUpdate(a, item, "api/test", "login", optString{}, nil, "", "", "", false, false, false, "", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if upd1["folderId"] != "folder-1" {
		t.Fatalf("folderId not preserved: %v", upd1["folderId"])
	}

	// 2. folder set to new folderID
	upd2, err := buildUpdate(a, item, "api/test", "login", optString{}, nil, "", "", "", false, false, false, "folder-2", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if upd2["folderId"] != "folder-2" {
		t.Fatalf("folderId not updated: %v", upd2["folderId"])
	}

	// 3. folder set to empty string (move to root) -> folderId nil
	upd3, err := buildUpdate(a, item, "api/test", "login", optString{}, nil, "", "", "", false, false, false, "", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if upd3["folderId"] != nil {
		t.Fatalf("folderId not cleared to nil: %v", upd3["folderId"])
	}
}

func TestBuildNewItemFolder(t *testing.T) {
	a := testApp()

	// With folderID
	b1, err := buildNewItem(a, "api/test", "login", optString{}, nil, "pw", "", "", "fid-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if b1["folderId"] != "fid-1" {
		t.Fatalf("expected folderId fid-1, got %v", b1["folderId"])
	}

	// Without folderID
	b2, err := buildNewItem(a, "standalone", "login", optString{}, nil, "pw", "", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := b2["folderId"]; ok {
		t.Fatalf("folderId should not be set when empty, got %v", b2["folderId"])
	}
}
