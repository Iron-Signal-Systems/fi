// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestApproval2LegacyRuntimePaths(
	t *testing.T,
) {
	t.Parallel()

	report :=
		Report{
			Services: []ServiceState{
				{
					BinaryPath: `"C:\Program Files\FI\fi.exe" -service`,
					Name:       "FICollector",
					Presence:   presencePresent,
				},
				{
					BinaryPath: `"C:\Program Files\FI\fi-usn.exe"`,
					Name:       "FIUSNReader",
					Presence:   presencePresent,
				},
				{
					BinaryPath: `"C:\Program Files\FI\fi-obj.exe"`,
					Name:       "FIObjReader",
					Presence:   presencePresent,
				},
				{
					BinaryPath: `"C:\Program Files\FI\fi-crl-refresh.exe"`,
					Name:       "FICRLRefresher",
					Presence:   presencePresent,
				},
				{
					BinaryPath: `"C:\Program Files\FI\fi-sender.exe"`,
					Name:       "FISender",
					Presence:   presencePresent,
				},
			},
		}

	got :=
		approval2LegacyRuntimePaths(
			report,
		)

	want :=
		[]string{
			`C:\Program Files\FI\fi.exe`,
			`C:\Program Files\FI\fi-usn.exe`,
			`C:\Program Files\FI\fi-obj.exe`,
			`C:\Program Files\FI\fi-crl-refresh.exe`,
		}

	if !reflect.DeepEqual(
		got,
		want,
	) {
		t.Fatalf(
			"legacy runtime paths=%v want=%v",
			got,
			want,
		)
	}
}

func TestApproval2LegacyRuntimePathsIgnoreNewNames(
	t *testing.T,
) {
	t.Parallel()

	report :=
		Report{
			Services: []ServiceState{
				{
					BinaryPath: `"C:\Program Files\FI\fi-collector.exe" -service`,
					Name:       "FICollector",
					Presence:   presencePresent,
				},
				{
					BinaryPath: `"C:\Program Files\FI\fi-usn-reader.exe"`,
					Name:       "FIUSNReader",
					Presence:   presencePresent,
				},
				{
					BinaryPath: `"C:\Program Files\FI\fi-obj-reader.exe"`,
					Name:       "FIObjReader",
					Presence:   presencePresent,
				},
				{
					BinaryPath: `"C:\Program Files\FI\fi-crl-refresher.exe"`,
					Name:       "FICRLRefresher",
					Presence:   presencePresent,
				},
			},
		}

	got :=
		approval2LegacyRuntimePaths(
			report,
		)

	if len(got) != 0 {
		t.Fatalf(
			"new runtime paths were classified as legacy: %v",
			got,
		)
	}
}

func TestRemoveApproval2LegacyRuntimeFiles(
	t *testing.T,
) {
	t.Parallel()

	path :=
		filepath.Join(
			t.TempDir(),
			"fi.exe",
		)

	if err :=
		os.WriteFile(
			path,
			[]byte("accepted legacy FI runtime"),
			0o600,
		); err != nil {
		t.Fatal(err)
	}

	hash, err :=
		fileSHA256(
			path,
		)
	if err != nil {
		t.Fatal(err)
	}

	err =
		removeApproval2LegacyRuntimeFiles(
			[]approval2LegacyRuntimeFile{
				{
					Path:   path,
					SHA256: hash,
				},
			},
		)
	if err != nil {
		t.Fatal(err)
	}

	if _, err :=
		os.Lstat(
			path,
		); !os.IsNotExist(
		err,
	) {
		t.Fatalf(
			"legacy runtime was not retired: %v",
			err,
		)
	}
}

func TestRemoveApproval2LegacyRuntimeFilesRejectsChangedFile(
	t *testing.T,
) {
	t.Parallel()

	path :=
		filepath.Join(
			t.TempDir(),
			"fi-usn.exe",
		)

	if err :=
		os.WriteFile(
			path,
			[]byte("reviewed legacy FI runtime"),
			0o600,
		); err != nil {
		t.Fatal(err)
	}

	hash, err :=
		fileSHA256(
			path,
		)
	if err != nil {
		t.Fatal(err)
	}

	if err :=
		os.WriteFile(
			path,
			[]byte("changed after review"),
			0o600,
		); err != nil {
		t.Fatal(err)
	}

	err =
		removeApproval2LegacyRuntimeFiles(
			[]approval2LegacyRuntimeFile{
				{
					Path:   path,
					SHA256: hash,
				},
			},
		)

	if err == nil {
		t.Fatal(
			"changed legacy runtime was retired",
		)
	}

	if !strings.Contains(
		err.Error(),
		"refusing to retire changed legacy FI runtime",
	) {
		t.Fatalf(
			"unexpected changed-file error: %v",
			err,
		)
	}

	if _, err :=
		os.Lstat(
			path,
		); err != nil {
		t.Fatalf(
			"changed legacy runtime was removed: %v",
			err,
		)
	}
}
