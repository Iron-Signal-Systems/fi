// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package transportcrl

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestReplaceExistingFileWithBackup(
	t *testing.T,
) {
	directory := t.TempDir()

	active := filepath.Join(
		directory,
		"active.crl.pem",
	)

	replacement := filepath.Join(
		directory,
		"active.crl.pem.fi-new-test",
	)

	backup := filepath.Join(
		directory,
		"active.crl.pem.fi-backup-test",
	)

	writeReplacementTestFile(
		t,
		active,
		[]byte("old-active"),
	)

	writeReplacementTestFile(
		t,
		replacement,
		[]byte("new-candidate"),
	)

	if err := ReplaceExistingFileWithBackup(
		active,
		replacement,
		backup,
	); err != nil {
		t.Fatal(err)
	}

	assertReplacementTestFile(
		t,
		active,
		[]byte("new-candidate"),
	)

	assertReplacementTestFile(
		t,
		backup,
		[]byte("old-active"),
	)

	if _, err := os.Stat(
		replacement,
	); !errors.Is(
		err,
		os.ErrNotExist,
	) {
		t.Fatalf(
			"replacement stage still exists; err=%v",
			err,
		)
	}
}

func TestReplaceExistingFileWithBackupRejectsExistingBackup(
	t *testing.T,
) {
	directory := t.TempDir()

	active := filepath.Join(
		directory,
		"active.crl.pem",
	)

	replacement := filepath.Join(
		directory,
		"active.crl.pem.fi-new-test",
	)

	backup := filepath.Join(
		directory,
		"active.crl.pem.fi-backup-test",
	)

	writeReplacementTestFile(
		t,
		active,
		[]byte("old-active"),
	)

	writeReplacementTestFile(
		t,
		replacement,
		[]byte("new-candidate"),
	)

	writeReplacementTestFile(
		t,
		backup,
		[]byte("existing-backup"),
	)

	err := ReplaceExistingFileWithBackup(
		active,
		replacement,
		backup,
	)

	if err == nil {
		t.Fatal(
			"preexisting backup was unexpectedly accepted",
		)
	}

	assertReplacementTestFile(
		t,
		active,
		[]byte("old-active"),
	)

	assertReplacementTestFile(
		t,
		replacement,
		[]byte("new-candidate"),
	)

	assertReplacementTestFile(
		t,
		backup,
		[]byte("existing-backup"),
	)
}

func TestReplaceExistingFileWithBackupRejectsDifferentDirectory(
	t *testing.T,
) {
	activeDirectory := t.TempDir()
	replacementDirectory := t.TempDir()

	active := filepath.Join(
		activeDirectory,
		"active.crl.pem",
	)

	replacement := filepath.Join(
		replacementDirectory,
		"candidate.crl.pem",
	)

	backup := filepath.Join(
		activeDirectory,
		"backup.crl.pem",
	)

	writeReplacementTestFile(
		t,
		active,
		[]byte("old-active"),
	)

	writeReplacementTestFile(
		t,
		replacement,
		[]byte("new-candidate"),
	)

	err := ReplaceExistingFileWithBackup(
		active,
		replacement,
		backup,
	)

	if err == nil {
		t.Fatal(
			"cross-directory replacement was unexpectedly accepted",
		)
	}

	assertReplacementTestFile(
		t,
		active,
		[]byte("old-active"),
	)

	assertReplacementTestFile(
		t,
		replacement,
		[]byte("new-candidate"),
	)

	if _, err := os.Stat(
		backup,
	); !errors.Is(
		err,
		os.ErrNotExist,
	) {
		t.Fatalf(
			"backup unexpectedly created; err=%v",
			err,
		)
	}
}

func TestReplaceExistingFileWithBackupRejectsMissingReplacement(
	t *testing.T,
) {
	directory := t.TempDir()

	active := filepath.Join(
		directory,
		"active.crl.pem",
	)

	replacement := filepath.Join(
		directory,
		"missing.crl.pem",
	)

	backup := filepath.Join(
		directory,
		"backup.crl.pem",
	)

	writeReplacementTestFile(
		t,
		active,
		[]byte("old-active"),
	)

	err := ReplaceExistingFileWithBackup(
		active,
		replacement,
		backup,
	)

	if err == nil {
		t.Fatal(
			"missing replacement file was unexpectedly accepted",
		)
	}

	assertReplacementTestFile(
		t,
		active,
		[]byte("old-active"),
	)

	if _, err := os.Stat(
		backup,
	); !errors.Is(
		err,
		os.ErrNotExist,
	) {
		t.Fatalf(
			"backup unexpectedly created; err=%v",
			err,
		)
	}
}

func assertReplacementTestFile(
	t *testing.T,
	path string,
	want []byte,
) {
	t.Helper()

	got, err := os.ReadFile(
		path,
	)
	if err != nil {
		t.Fatal(err)
	}

	if string(got) != string(want) {
		t.Fatalf(
			"%s content=%q want=%q",
			path,
			got,
			want,
		)
	}
}

func writeReplacementTestFile(
	t *testing.T,
	path string,
	value []byte,
) {
	t.Helper()

	if err := os.WriteFile(
		path,
		value,
		0600,
	); err != nil {
		t.Fatal(err)
	}
}
