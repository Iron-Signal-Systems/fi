// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package ntfs

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func TestCollectPathDirectorySymlinkReparse(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	link := filepath.Join(root, "directory-link")

	if output, err := exec.Command("cmd", "/c", "mklink", "/D", link, outside).CombinedOutput(); err != nil {
		t.Skipf("directory symlink unavailable: %v: %s", err, output)
	}

	observation, err := CollectPath(context.Background(), "scope-reparse-test", root, link)
	if err != nil {
		t.Fatal(err)
	}

	assertReparseObservation(
		t,
		observation,
		records.SubjectDirectory,
		"0xA000000C",
		"IO_REPARSE_TAG_SYMLINK",
	)
}

func TestCollectPathFileSymlinkReparse(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	target := filepath.Join(outside, "target.txt")
	link := filepath.Join(root, "file-link.txt")

	if err := os.WriteFile(target, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}

	if output, err := exec.Command("cmd", "/c", "mklink", link, target).CombinedOutput(); err != nil {
		t.Skipf("file symlink unavailable: %v: %s", err, output)
	}

	observation, err := CollectPath(context.Background(), "scope-reparse-test", root, link)
	if err != nil {
		t.Fatal(err)
	}

	assertReparseObservation(
		t,
		observation,
		records.SubjectFile,
		"0xA000000C",
		"IO_REPARSE_TAG_SYMLINK",
	)
}

func TestCollectPathJunctionReparse(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	junction := filepath.Join(root, "junction")

	if output, err := exec.Command("cmd", "/c", "mklink", "/J", junction, outside).CombinedOutput(); err != nil {
		t.Fatalf("create junction: %v: %s", err, output)
	}

	observation, err := CollectPath(context.Background(), "scope-reparse-test", root, junction)
	if err != nil {
		t.Fatal(err)
	}

	assertReparseObservation(
		t,
		observation,
		records.SubjectDirectory,
		"0xA0000003",
		"IO_REPARSE_TAG_MOUNT_POINT",
	)
}

func assertReparseObservation(
	t *testing.T,
	observation Observation,
	wantSubject records.SubjectKind,
	wantTag string,
	wantTagName string,
) {
	t.Helper()

	if observation.SubjectKind != wantSubject {
		t.Fatalf("subject kind = %q, want %q", observation.SubjectKind, wantSubject)
	}
	if observation.Reparse.State != records.ReparseStatePresent {
		t.Fatalf("reparse state = %q, want %q", observation.Reparse.State, records.ReparseStatePresent)
	}
	if observation.Reparse.Tag != wantTag {
		t.Fatalf("reparse tag = %q, want %q", observation.Reparse.Tag, wantTag)
	}
	if observation.Reparse.TagName != wantTagName {
		t.Fatalf("reparse tag name = %q, want %q", observation.Reparse.TagName, wantTagName)
	}
}
