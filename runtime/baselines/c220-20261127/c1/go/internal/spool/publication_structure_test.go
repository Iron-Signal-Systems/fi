// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package spool

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestValidatePublishedSpoolStructureLockedAcceptsEmpty(
	t *testing.T,
) {
	dir :=
		t.TempDir()

	pairs, err :=
		ValidatePublishedSpoolStructureLocked(
			dir,
		)
	if err != nil {
		t.Fatal(err)
	}

	if pairs != 0 {
		t.Fatalf(
			"pairs = %d, want 0",
			pairs,
		)
	}
}

func TestValidatePublishedSpoolStructureLockedAcceptsCompletePairs(
	t *testing.T,
) {
	dir :=
		t.TempDir()

	writeStructureTestFile(
		t,
		dir,
		"batch-a.jsonl",
	)

	writeStructureTestFile(
		t,
		dir,
		"batch-a.manifest.json",
	)

	writeStructureTestFile(
		t,
		dir,
		"batch-b.jsonl",
	)

	writeStructureTestFile(
		t,
		dir,
		"batch-b.manifest.json",
	)

	pairs, err :=
		ValidatePublishedSpoolStructureLocked(
			dir,
		)
	if err != nil {
		t.Fatal(err)
	}

	if pairs != 2 {
		t.Fatalf(
			"pairs = %d, want 2",
			pairs,
		)
	}
}

func TestValidatePublishedSpoolStructureLockedRejectsOrphanData(
	t *testing.T,
) {
	dir :=
		t.TempDir()

	writeStructureTestFile(
		t,
		dir,
		"batch-orphan.jsonl",
	)

	_, err :=
		ValidatePublishedSpoolStructureLocked(
			dir,
		)

	if err == nil ||
		!strings.Contains(
			err.Error(),
			"no matching manifest",
		) {
		t.Fatalf(
			"error = %v, want missing-manifest error",
			err,
		)
	}
}

func TestValidatePublishedSpoolStructureLockedRejectsOrphanManifest(
	t *testing.T,
) {
	dir :=
		t.TempDir()

	writeStructureTestFile(
		t,
		dir,
		"batch-orphan.manifest.json",
	)

	_, err :=
		ValidatePublishedSpoolStructureLocked(
			dir,
		)

	if err == nil ||
		!strings.Contains(
			err.Error(),
			"no matching data file",
		) {
		t.Fatalf(
			"error = %v, want missing-data error",
			err,
		)
	}
}

func TestValidatePublishedSpoolStructureLockedRejectsOpen(
	t *testing.T,
) {
	dir :=
		t.TempDir()

	writeStructureTestFile(
		t,
		dir,
		"batch-live.open",
	)

	_, err :=
		ValidatePublishedSpoolStructureLocked(
			dir,
		)

	if err == nil ||
		!strings.Contains(
			err.Error(),
			"unexpected FI published spool artifact",
		) {
		t.Fatalf(
			"error = %v, want unexpected-artifact error",
			err,
		)
	}
}

func TestValidatePublishedSpoolStructureLockedRejectsUnexpectedFile(
	t *testing.T,
) {
	dir :=
		t.TempDir()

	writeStructureTestFile(
		t,
		dir,
		"unexpected.bin",
	)

	_, err :=
		ValidatePublishedSpoolStructureLocked(
			dir,
		)

	if err == nil ||
		!strings.Contains(
			err.Error(),
			"unexpected FI published spool artifact",
		) {
		t.Fatalf(
			"error = %v, want unexpected-artifact error",
			err,
		)
	}
}

func TestValidatePublishedSpoolStructureLockedRejectsDirectory(
	t *testing.T,
) {
	dir :=
		t.TempDir()

	if err :=
		os.Mkdir(
			filepath.Join(
				dir,
				"batch-directory.jsonl",
			),
			0o700,
		); err != nil {
		t.Fatal(err)
	}

	_, err :=
		ValidatePublishedSpoolStructureLocked(
			dir,
		)

	if err == nil ||
		!strings.Contains(
			err.Error(),
			"not a regular file",
		) {
		t.Fatalf(
			"error = %v, want non-regular-file error",
			err,
		)
	}
}

func TestValidatePublishedSpoolStructureLockedRejectsSymlink(
	t *testing.T,
) {
	dir :=
		t.TempDir()

	target :=
		filepath.Join(
			dir,
			"target",
		)

	if err :=
		os.WriteFile(
			target,
			[]byte("target"),
			0o600,
		); err != nil {
		t.Fatal(err)
	}

	link :=
		filepath.Join(
			dir,
			"batch-link.jsonl",
		)

	if err :=
		os.Symlink(
			target,
			link,
		); err != nil {

		if runtime.GOOS == "windows" {
			t.Skipf(
				"Windows test account cannot create symlink: %v",
				err,
			)
		}

		t.Fatal(err)
	}

	if err :=
		os.Remove(
			target,
		); err != nil {
		t.Fatal(err)
	}

	_, err :=
		ValidatePublishedSpoolStructureLocked(
			dir,
		)

	if err == nil ||
		!strings.Contains(
			err.Error(),
			"symbolic link",
		) {
		t.Fatalf(
			"error = %v, want symbolic-link error",
			err,
		)
	}
}

func writeStructureTestFile(
	t *testing.T,
	dir string,
	name string,
) {
	t.Helper()

	if err :=
		os.WriteFile(
			filepath.Join(
				dir,
				name,
			),
			[]byte("{}\n"),
			0o600,
		); err != nil {
		t.Fatal(err)
	}
}
