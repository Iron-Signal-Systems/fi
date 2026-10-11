// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"bytes"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestApplicationBinaryFileClassification(
	t *testing.T,
) {
	directory := t.TempDir()

	target := filepath.Join(
		directory,
		"fi-test",
	)

	spec := applicationBinaryTestSpec(
		target,
	)

	if state := classifyApplicationBinaryFile(
		spec,
	); state != applicationBinaryFileAbsent {
		t.Fatalf(
			"absent state = %s",
			state,
		)
	}

	if err := os.WriteFile(
		target,
		[]byte("foreign\n"),
		0o555,
	); err != nil {
		t.Fatal(err)
	}

	if state := classifyApplicationBinaryFile(
		spec,
	); state != applicationBinaryFileForeignCollision {
		t.Fatalf(
			"foreign state = %s",
			state,
		)
	}

	if err := os.Remove(
		target,
	); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(
		target,
		spec.Content,
		0o644,
	); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(
		target,
		0o644,
	); err != nil {
		t.Fatal(err)
	}

	if state := classifyApplicationBinaryFile(
		spec,
	); state != applicationBinaryFileOwnedDrift {
		t.Fatalf(
			"drift state = %s",
			state,
		)
	}

	if err := os.Chmod(
		target,
		spec.Mode,
	); err != nil {
		t.Fatal(err)
	}

	if state := classifyApplicationBinaryFile(
		spec,
	); state != applicationBinaryFileOwnedMatch {
		t.Fatalf(
			"match state = %s",
			state,
		)
	}
}

func TestApplicationBinaryPlan(
	t *testing.T,
) {
	releaseDirectory := t.TempDir()

	receiverContent :=
		[]byte("receiver-binary\n")

	ingestContent :=
		[]byte("ingest-binary\n")

	if err := os.WriteFile(
		filepath.Join(
			releaseDirectory,
			"fi-receiver",
		),
		receiverContent,
		0o755,
	); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(
		filepath.Join(
			releaseDirectory,
			"fi-ingest-worker",
		),
		ingestContent,
		0o755,
	); err != nil {
		t.Fatal(err)
	}

	receiverRoot := filepath.Join(
		t.TempDir(),
		"receiver",
	)

	ingestRoot := filepath.Join(
		t.TempDir(),
		"ingest",
	)

	config := Config{
		values: map[string]string{
			"FI_RECEIVER_ROOT": receiverRoot,
			"FI_INGEST_ROOT":   ingestRoot,
		},
	}

	plan, err := buildApplicationBinaryPlan(
		config,
		releaseDirectory,
	)
	if err != nil {
		t.Fatalf(
			"buildApplicationBinaryPlan() error = %v",
			err,
		)
	}

	if len(plan.Parents) != 2 {
		t.Fatalf(
			"parent count = %d, want 2",
			len(plan.Parents),
		)
	}

	if len(plan.Files) != 2 {
		t.Fatalf(
			"file count = %d, want 2",
			len(plan.Files),
		)
	}

	expectedTargets := []string{
		filepath.Join(
			receiverRoot,
			"usr/local/sbin/fi-receiver",
		),
		filepath.Join(
			ingestRoot,
			"usr/local/sbin/fi-ingest-worker",
		),
	}

	expectedContent := [][]byte{
		receiverContent,
		ingestContent,
	}

	for index, spec := range plan.Files {
		if spec.Target != expectedTargets[index] {
			t.Fatalf(
				"target[%d] = %q, want %q",
				index,
				spec.Target,
				expectedTargets[index],
			)
		}

		if spec.Mode != 0o555 {
			t.Fatalf(
				"mode[%d] = %o, want 0555",
				index,
				spec.Mode,
			)
		}

		if spec.UID != 0 ||
			spec.GID != 0 {
			t.Fatalf(
				"ownership[%d] = %d:%d, want 0:0",
				index,
				spec.UID,
				spec.GID,
			)
		}

		if !bytes.Equal(
			spec.Content,
			expectedContent[index],
		) {
			t.Fatalf(
				"content[%d] differs from release source",
				index,
			)
		}
	}
}

func TestPublishAbsentApplicationBinary(
	t *testing.T,
) {
	target := filepath.Join(
		t.TempDir(),
		"fi-test",
	)

	spec := applicationBinaryTestSpec(
		target,
	)

	if err := publishAbsentApplicationBinary(
		spec,
	); err != nil {
		t.Fatalf(
			"publishAbsentApplicationBinary() error = %v",
			err,
		)
	}

	if state := classifyApplicationBinaryFile(
		spec,
	); state != applicationBinaryFileOwnedMatch {
		t.Fatalf(
			"state = %s, want OWNED_MATCH",
			state,
		)
	}
}

func applicationBinaryTestSpec(
	target string,
) applicationBinaryFileSpec {
	info, err := os.Stat(
		filepath.Dir(
			target,
		),
	)
	if err != nil {
		panic(err)
	}

	stat, ok :=
		info.Sys().(*syscall.Stat_t)
	if !ok {
		panic(
			"test directory stat is not syscall.Stat_t",
		)
	}

	return applicationBinaryFileSpec{
		Content: []byte(
			"binary-content\n",
		),
		GID: uint64(
			stat.Gid,
		),
		Mode:   0o555,
		Role:   "test-binary",
		Target: target,
		UID: uint64(
			stat.Uid,
		),
	}
}
