// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestClassifyHostFileParentAbsent(t *testing.T) {
	spec := hostFileParentSpec{
		GID:  0,
		Mode: 0o755,
		Path: filepath.Join(
			t.TempDir(),
			"missing",
		),
		UID: 0,
	}

	if state := classifyHostFileParent(
		spec,
	); state != hostFileParentAbsent {
		t.Fatalf(
			"state = %s, want ABSENT",
			state,
		)
	}
}

func TestClassifyHostFileParentSafeMatch(t *testing.T) {
	directory := t.TempDir()

	info, err := os.Stat(
		directory,
	)
	if err != nil {
		t.Fatal(err)
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal(
			"test directory stat is not syscall.Stat_t",
		)
	}

	spec := hostFileParentSpec{
		GID:  uint64(stat.Gid),
		Mode: info.Mode().Perm(),
		Path: directory,
		UID:  uint64(stat.Uid),
	}

	if state := classifyHostFileParent(
		spec,
	); state != hostFileParentSafeMatch {
		t.Fatalf(
			"state = %s, want SAFE_MATCH",
			state,
		)
	}
}

func TestClassifyHostFileParentUnsafeMetadata(t *testing.T) {
	directory := t.TempDir()

	info, err := os.Stat(
		directory,
	)
	if err != nil {
		t.Fatal(err)
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal(
			"test directory stat is not syscall.Stat_t",
		)
	}

	mode := os.FileMode(0o700)

	if info.Mode().Perm() == mode {
		mode = 0o755
	}

	spec := hostFileParentSpec{
		GID:  uint64(stat.Gid),
		Mode: mode,
		Path: directory,
		UID:  uint64(stat.Uid),
	}

	if state := classifyHostFileParent(
		spec,
	); state != hostFileParentUnsafe {
		t.Fatalf(
			"state = %s, want UNSAFE",
			state,
		)
	}
}

func TestClassifyHostFileParentRejectsNonDirectory(t *testing.T) {
	target := filepath.Join(
		t.TempDir(),
		"not-directory",
	)

	if err := os.WriteFile(
		target,
		[]byte("not a directory\n"),
		0o644,
	); err != nil {
		t.Fatal(err)
	}

	spec := hostFileParentSpec{
		GID:  0,
		Mode: 0o755,
		Path: target,
		UID:  0,
	}

	if state := classifyHostFileParent(
		spec,
	); state != hostFileParentUnsafe {
		t.Fatalf(
			"state = %s, want UNSAFE",
			state,
		)
	}
}
