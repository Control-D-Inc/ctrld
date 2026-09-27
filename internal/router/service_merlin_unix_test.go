//go:build linux

package router

import (
	"bytes"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestCreateMerlinSharedHookStubIgnoresRestrictiveUmask(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "services-start")

	oldUmask := syscall.Umask(0777)
	defer syscall.Umask(oldUmask)

	if err := createMerlinSharedHookStub(path); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0755 {
		t.Fatalf("shared hook mode = %o, want 755", got)
	}

	buf, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf) != "#!/bin/sh\n" {
		t.Fatalf("shared hook contents = %q", buf)
	}
}


func TestCreateMerlinSharedHookStubDoesNotClobberExistingTarget(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "services-start")
	want := []byte("#!/bin/sh\necho addon\n")
	if err := os.WriteFile(path, want, 0755); err != nil {
		t.Fatal(err)
	}

	if err := createMerlinSharedHookStub(path); !os.IsExist(err) {
		t.Fatalf("createMerlinSharedHookStub error = %v, want already-exists", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("existing shared hook was modified:\nwant %q\ngot  %q", want, got)
	}
}

func TestReplaceMerlinStartupScriptAtomicallyPreservesReplacedTarget(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ctrld.startup")
	legacy := []byte("#!/bin/sh\necho legacy\n")
	current := []byte("#!/bin/sh\necho current\n")
	replacement := []byte("#!/bin/sh\necho user replacement\n")

	if err := os.WriteFile(path, legacy, 0755); err != nil {
		t.Fatal(err)
	}
	originalInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	replacementPath := filepath.Join(dir, "replacement")
	if err := os.WriteFile(replacementPath, replacement, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacementPath, path); err != nil {
		t.Fatal(err)
	}

	if err := replaceMerlinStartupScriptAtomically(path, current, legacy, originalInfo); err == nil {
		t.Fatal("expected concurrent inode replacement to abort migration")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(replacement) {
		t.Fatalf("replacement target changed: got %q want %q", got, replacement)
	}
}

func TestReplaceMerlinStartupScriptAtomicallyPreservesInPlaceEdit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ctrld.startup")
	legacy := []byte("#!/bin/sh\necho legacy\n")
	current := []byte("#!/bin/sh\necho current\n")
	edited := []byte("#!/bin/sh\necho edited in place\n")

	if err := os.WriteFile(path, legacy, 0755); err != nil {
		t.Fatal(err)
	}
	originalInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, edited, 0755); err != nil {
		t.Fatal(err)
	}

	if err := replaceMerlinStartupScriptAtomically(path, current, legacy, originalInfo); err == nil {
		t.Fatal("expected concurrent in-place edit to abort migration")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(edited) {
		t.Fatalf("in-place edit changed: got %q want %q", got, edited)
	}
}
