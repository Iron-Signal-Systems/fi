// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package checkpoint

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	value, _, _ := testState()
	path := filepath.Join(t.TempDir(), "state", "manual-test-usn.json")
	if err := Save(path, value); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded != value {
		t.Fatalf("round trip mismatch:\nwant: %+v\n got: %+v", value, loaded)
	}
}

func TestSaveReplacesExistingCheckpoint(t *testing.T) {
	value, _, _ := testState()
	path := filepath.Join(t.TempDir(), "manual-test-usn.json")
	if err := Save(path, value); err != nil {
		t.Fatal(err)
	}
	value.NextUSN = "175"
	value.UpdatedAt = "2026-08-22T13:02:00Z"
	if err := Save(path, value); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.NextUSN != "175" {
		t.Fatalf("expected replacement checkpoint, got %+v", loaded)
	}
}

func TestLoadRejectsCorruptCheckpoint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manual-test-usn.json")
	if err := os.WriteFile(path, []byte(`{"version":"fi-usn-checkpoint/0.1","scope_id":`), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if !errors.Is(err, ErrInvalidCheckpoint) {
		t.Fatalf("expected ErrInvalidCheckpoint, got %v", err)
	}
}

func TestAdvancePersistsOnlyExpectedCheckpoint(t *testing.T) {
	value, root, journal := testState()
	path := filepath.Join(t.TempDir(), "manual-test-usn.json")
	if err := Save(path, value); err != nil {
		t.Fatal(err)
	}
	assessment, err := Assess(value, root, journal)
	if err != nil {
		t.Fatal(err)
	}
	advanced, err := Advance(path, assessment, "150", "175")
	if err != nil {
		t.Fatal(err)
	}
	if advanced.NextUSN != "175" {
		t.Fatalf("unexpected advanced checkpoint: %+v", advanced)
	}
	if _, err := Advance(path, assessment, "150", "180"); !errors.Is(err, ErrCheckpointConflict) {
		t.Fatalf("expected stale checkpoint conflict, got %v", err)
	}
}
