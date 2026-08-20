// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package ntfs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func TestWalkGovernedRootCollectsNestedTree(t *testing.T) {
	root := t.TempDir()

	levelOne := filepath.Join(root, "level-one")
	levelTwo := filepath.Join(levelOne, "level-two")

	if err := os.MkdirAll(levelTwo, 0o755); err != nil {
		t.Fatal(err)
	}

	rootFile := filepath.Join(root, "root.txt")
	levelOneFile := filepath.Join(levelOne, "one.txt")
	levelTwoFile := filepath.Join(levelTwo, "two.txt")

	if err := os.WriteFile(rootFile, []byte("root"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(levelOneFile, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(levelTwoFile, []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}

	// ADS belongs to levelTwoFile. It must be discovered by CollectPath, not
	// emitted as a separate filesystem object by the walker.
	if err := os.WriteFile(
		levelTwoFile+`:payload`,
		[]byte("hidden stream"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	want := map[string]records.SubjectKind{
		filepath.Clean(root):         records.SubjectDirectory,
		filepath.Clean(levelOne):     records.SubjectDirectory,
		filepath.Clean(levelTwo):     records.SubjectDirectory,
		filepath.Clean(rootFile):     records.SubjectFile,
		filepath.Clean(levelOneFile): records.SubjectFile,
		filepath.Clean(levelTwoFile): records.SubjectFile,
	}

	got := make(map[string]records.SubjectKind)
	foundADS := false

	err := WalkGovernedRoot(
		context.Background(),
		"scope-walk-test",
		root,
		func(
			path string,
			observation Observation,
			collectErr error,
		) error {
			if collectErr != nil {
				t.Errorf("collect %q: %v", path, collectErr)
				return nil
			}

			cleanPath := filepath.Clean(path)
			got[cleanPath] = observation.SubjectKind

			if cleanPath == filepath.Clean(levelTwoFile) {
				for _, stream := range observation.StreamInventory.Streams {
					if stream.Identity.Kind == records.StreamNamedData {
						foundADS = true
					}
				}
			}

			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != len(want) {
		t.Fatalf("walk returned %d objects, want %d: %+v", len(got), len(want), got)
	}

	for path, wantKind := range want {
		gotKind, ok := got[path]
		if !ok {
			t.Fatalf("walk did not return %q", path)
		}

		if gotKind != wantKind {
			t.Fatalf(
				"subject kind for %q = %s, want %s",
				path,
				gotKind,
				wantKind,
			)
		}
	}

	if !foundADS {
		t.Fatal("nested file observation did not contain named data stream")
	}
}

func TestWalkGovernedRootRejectsFileRoot(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "not-a-directory.txt")

	if err := os.WriteFile(file, []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := WalkGovernedRoot(
		context.Background(),
		"scope-walk-test",
		file,
		func(string, Observation, error) error {
			return nil
		},
	)

	if !errors.Is(err, ErrWalkRootNotDirectory) {
		t.Fatalf("error = %v, want ErrWalkRootNotDirectory", err)
	}
}
