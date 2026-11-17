package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMigrationPreservesNewAndOld(t *testing.T) {
	root := t.TempDir()
	old := filepath.Join(root, "old")
	newP := filepath.Join(root, "new")
	os.MkdirAll(old, 0700)
	os.WriteFile(filepath.Join(old, "profile.dpapi"), []byte("old"), 0600)
	if err := migrateProfile(newP, old); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(newP, "profile.dpapi"))
	if string(b) != "old" {
		t.Fatal("not imported")
	}
	os.WriteFile(filepath.Join(newP, "profile.dpapi"), []byte("new"), 0600)
	if err := migrateProfile(newP, old); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(filepath.Join(newP, "profile.dpapi"))
	if string(b) != "new" {
		t.Fatal("overwritten")
	}
	b, _ = os.ReadFile(filepath.Join(old, "profile.dpapi"))
	if string(b) != "old" {
		t.Fatal("changed old")
	}
}
