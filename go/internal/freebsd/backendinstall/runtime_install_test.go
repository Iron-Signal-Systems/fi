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

func TestRuntimeFileClassification(
	t *testing.T,
) {
	directory := t.TempDir()

	target := filepath.Join(
		directory,
		"runtime-file",
	)

	spec := runtimeTestFileSpec(
		target,
	)

	if state := classifyRuntimeFile(
		spec,
	); state != runtimeFileAbsent {
		t.Fatalf(
			"absent state = %s",
			state,
		)
	}

	if err := os.WriteFile(
		target,
		[]byte("foreign\n"),
		0o644,
	); err != nil {
		t.Fatal(err)
	}

	if state := classifyRuntimeFile(
		spec,
	); state != runtimeFileForeignCollision {
		t.Fatalf(
			"foreign state = %s",
			state,
		)
	}

	if err := os.WriteFile(
		target,
		[]byte(
			runtimeFileMarker+
				"\n"+
				"# FI-ROLE: test\n"+
				"drift\n",
		),
		0o644,
	); err != nil {
		t.Fatal(err)
	}

	if state := classifyRuntimeFile(
		spec,
	); state != runtimeFileOwnedDrift {
		t.Fatalf(
			"drift state = %s",
			state,
		)
	}
}

func TestPublishAbsentRuntimeFile(
	t *testing.T,
) {
	target := filepath.Join(
		t.TempDir(),
		"runtime-file",
	)

	spec := runtimeTestFileSpec(
		target,
	)

	if err := publishAbsentRuntimeFile(
		spec,
	); err != nil {
		t.Fatalf(
			"publishAbsentRuntimeFile() error = %v",
			err,
		)
	}

	if state := classifyRuntimeFile(
		spec,
	); state != runtimeFileOwnedMatch {
		t.Fatalf(
			"state = %s, want OWNED_MATCH",
			state,
		)
	}
}

func TestRuntimeFileHardLinkIsDrift(
	t *testing.T,
) {
	directory := t.TempDir()

	target := filepath.Join(
		directory,
		"runtime-file",
	)

	spec := runtimeTestFileSpec(
		target,
	)

	if err := publishAbsentRuntimeFile(
		spec,
	); err != nil {
		t.Fatal(err)
	}

	other := filepath.Join(
		directory,
		"runtime-file.other",
	)

	if err := os.Link(
		target,
		other,
	); err != nil {
		t.Fatal(err)
	}

	if state := classifyRuntimeFile(
		spec,
	); state != runtimeFileOwnedDrift {
		t.Fatalf(
			"state = %s, want OWNED_DRIFT",
			state,
		)
	}
}

func runtimeTestFileSpec(
	target string,
) runtimeFileSpec {
	info, err := os.Stat(
		filepath.Dir(
			target,
		),
	)
	if err != nil {
		panic(err)
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		panic(
			"test directory stat is not syscall.Stat_t",
		)
	}

	return runtimeFileSpec{
		Content: []byte(
			runtimeFileMarker +
				"\n" +
				"# FI-ROLE: test\n",
		),
		GID: uint64(
			stat.Gid,
		),
		Mode:   0o644,
		Role:   "test",
		Target: target,
		UID: uint64(
			stat.Uid,
		),
	}
}
