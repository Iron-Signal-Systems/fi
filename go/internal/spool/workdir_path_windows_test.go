// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package spool

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCollectorWorkDirMatchesCollectorWorkPathForExistingSpool(
	t *testing.T,
) {
	t.Parallel()

	root :=
		t.TempDir()

	spoolDir :=
		filepath.Join(
			root,
			"spool",
		)

	if err :=
		os.Mkdir(
			spoolDir,
			0o700,
		); err != nil {
		t.Fatal(err)
	}

	derived, err :=
		CollectorWorkPath(
			spoolDir,
		)
	if err != nil {
		t.Fatal(err)
	}

	resolved, err :=
		CollectorWorkDir(
			spoolDir,
		)
	if err != nil {
		t.Fatal(err)
	}

	// Windows may expose the configured path through an 8.3 alias while
	// GetFinalPathNameByHandleW returns the long physical name. Those are the
	// same directory identity and must not be compared as raw path strings.
	if !strings.EqualFold(
		filepath.Base(
			derived,
		),
		filepath.Base(
			resolved,
		),
	) {
		t.Fatalf(
			"collector work leaf differs: derived=%q resolved=%q",
			filepath.Base(derived),
			filepath.Base(resolved),
		)
	}

	derivedParent, err :=
		resolveDirectoryPath(
			filepath.Dir(
				derived,
			),
		)
	if err != nil {
		t.Fatalf(
			"resolve derived work parent: %v",
			err,
		)
	}

	resolvedParent, err :=
		resolveDirectoryPath(
			filepath.Dir(
				resolved,
			),
		)
	if err != nil {
		t.Fatalf(
			"resolve runtime work parent: %v",
			err,
		)
	}

	if !strings.EqualFold(
		filepath.Clean(
			derivedParent,
		),
		filepath.Clean(
			resolvedParent,
		),
	) {
		t.Fatalf(
			"collector work physical parent differs: derived=%q resolved=%q",
			derivedParent,
			resolvedParent,
		)
	}
}
func TestCollectorWorkPathDerivesSiblingBeforeSpoolExists(
	t *testing.T,
) {
	t.Parallel()

	tests :=
		[]struct {
			name      string
			spoolName string
		}{
			{
				name:      "default spool name",
				spoolName: "spool",
			},
			{
				name:      "non-default spool name",
				spoolName: "customer-spool",
			},
		}

	for _, test := range tests {
		test := test

		t.Run(
			test.name,
			func(t *testing.T) {
				t.Parallel()

				root :=
					t.TempDir()

				spoolDir :=
					filepath.Join(
						root,
						test.spoolName,
					)

				if _, err :=
					os.Lstat(
						spoolDir,
					); !os.IsNotExist(
					err,
				) {
					t.Fatalf(
						"test spool unexpectedly exists: %v",
						err,
					)
				}

				got, err :=
					CollectorWorkPath(
						spoolDir,
					)
				if err != nil {
					t.Fatal(err)
				}

				want :=
					filepath.Join(
						root,
						".fi-"+
							test.spoolName+
							"-collector-work",
					)

				if filepath.Clean(
					got,
				) != filepath.Clean(
					want,
				) {
					t.Fatalf(
						"CollectorWorkPath=%q want=%q",
						got,
						want,
					)
				}
			},
		)
	}
}
