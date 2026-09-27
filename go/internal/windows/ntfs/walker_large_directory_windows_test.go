// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package ntfs

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func TestWalkGovernedRootCollectsLargeDirectory(t *testing.T) {
	root := t.TempDir()
	const fileCount = 300

	for index := 0; index < fileCount; index++ {
		name := filepath.Join(root, fmt.Sprintf("file-%04d.txt", index))
		if err := os.WriteFile(name, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// Valid self-relative security descriptor with no SACL present. The test
	// still exercises SACL acquisition for every object without coupling this
	// directory-batching proof to FIUSNReader availability.
	saclDescriptor := make([]byte, 20)
	saclDescriptor[0] = 1
	binary.LittleEndian.PutUint16(saclDescriptor[2:4], 0x8000)

	saclCalls := 0
	reader := func(
		ctx context.Context,
		governedRoot string,
		_ uint64,
		_ uint16,
	) ([]byte, error) {
		if ctx == nil {
			t.Fatal("injected SACL reader received nil context")
		}
		if governedRoot != root {
			t.Fatalf("governed root = %q, want %q", governedRoot, root)
		}
		saclCalls++
		return append([]byte(nil), saclDescriptor...), nil
	}

	seen := make(map[string]int, fileCount)
	err := walkGovernedRootWithSACLReader(
		context.Background(),
		"scope-large-directory-test",
		root,
		reader,
		func(path string, observation Observation, objectErr error) error {
			if objectErr != nil {
				return objectErr
			}
			if observation.SubjectKind == records.SubjectFile {
				seen[filepath.Clean(path)]++
			}
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(seen) != fileCount {
		t.Fatalf("walk saw %d unique files, want %d", len(seen), fileCount)
	}
	for index := 0; index < fileCount; index++ {
		path := filepath.Clean(filepath.Join(root, fmt.Sprintf("file-%04d.txt", index)))
		if seen[path] != 1 {
			t.Fatalf("walk count for %q = %d, want 1", path, seen[path])
		}
	}

	// Root + all 300 files must still traverse SACL acquisition. The injected
	// reader changes only the authority source, not the observation pipeline.
	if saclCalls != fileCount+1 {
		t.Fatalf("SACL reader calls = %d, want %d", saclCalls, fileCount+1)
	}
}
