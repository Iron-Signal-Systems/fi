// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package spool

import (
	"path/filepath"
	"testing"
)

func TestCollectorWorkDirIsSiblingOfPhysicalSpool(
	t *testing.T,
) {
	spoolDir :=
		t.TempDir()

	workDir, err :=
		CollectorWorkDir(
			spoolDir,
		)

	if err != nil {
		t.Fatal(err)
	}

	resolved, err :=
		resolveDirectoryPath(
			spoolDir,
		)

	if err != nil {
		t.Fatal(err)
	}

	if filepath.Dir(workDir) !=
		filepath.Dir(resolved) {
		t.Fatalf(
			"work directory parent = %q, want %q",
			filepath.Dir(workDir),
			filepath.Dir(resolved),
		)
	}

	expectedBase :=
		collectorWorkDirectoryPrefix +
			filepath.Base(resolved) +
			collectorWorkDirectorySuffix

	if filepath.Base(workDir) !=
		expectedBase {
		t.Fatalf(
			"work directory base = %q, want %q",
			filepath.Base(workDir),
			expectedBase,
		)
	}

	if filepath.Clean(workDir) ==
		filepath.Clean(resolved) {
		t.Fatal(
			"collector work directory equals active spool",
		)
	}
}
