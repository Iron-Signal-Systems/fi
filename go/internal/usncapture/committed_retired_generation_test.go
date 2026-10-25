// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usncapture

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportgeneration"
)

// retiredCommittedFixture uses the real committed capture queue and signed
// generation test fixture, then renames only the frozen source directory.
func retiredCommittedFixture(
	t *testing.T,
) (string, string, transportgeneration.PublishedGeneration) {
	t.Helper()

	stateDir, raw, sealed, _ := discoveredCommittedGenerationFixture(t)

	generationName := filepath.Base(raw)
	if !strings.HasPrefix(generationName, "generation-") {
		t.Fatalf("unexpected original generation name: %s", generationName)
	}

	generationID := strings.TrimPrefix(generationName, "generation-")
	retired := filepath.Join(
		filepath.Dir(raw),
		committedGenerationDirectoryName(generationID, true),
	)

	if err := os.Rename(raw, retired); err != nil {
		t.Fatal(err)
	}

	return stateDir, retired, sealed
}

func TestCommittedRetiredPreflightMatchesOriginalCustody(t *testing.T) {
	stateDir, raw, sealed, _ := discoveredCommittedGenerationFixture(t)
	ctx := context.Background()

	expected, err := VerifyDiscoveredCommittedGeneration(
		ctx, stateDir, raw, sealed.DirectoryPath, "m5d-source",
	)
	if err != nil {
		t.Fatal(err)
	}

	generationID := strings.TrimPrefix(filepath.Base(raw), "generation-")
	retired := filepath.Join(
		filepath.Dir(raw),
		committedGenerationDirectoryName(generationID, true),
	)

	if err := os.Rename(raw, retired); err != nil {
		t.Fatal(err)
	}

	actual, err := VerifyDiscoveredRetiredCommittedGeneration(
		ctx, stateDir, retired, sealed.DirectoryPath, "m5d-source",
	)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("retired custody changed: %+v / %+v", actual, expected)
	}

	if _, err := VerifyDiscoveredCommittedGeneration(
		ctx, stateDir, retired, sealed.DirectoryPath, "m5d-source",
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("ordinary frozen verifier accepted tombstone: %v", err)
	}

	if _, err := os.Stat(retired); err != nil {
		t.Fatalf("verification changed original custody: %v", err)
	}
}

func TestCommittedRetiredPreflightRejectsChangedPhysicalIdentity(
	t *testing.T,
) {
	stateDir, retired, sealed := retiredCommittedFixture(t)

	wrong := retired + "-different"
	if err := os.Rename(retired, wrong); err != nil {
		t.Fatal(err)
	}

	if _, err := VerifyDiscoveredRetiredCommittedGeneration(
		context.Background(),
		stateDir, wrong, sealed.DirectoryPath, "m5d-source",
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("incorrect tombstone identity accepted: %v", err)
	}
}

func TestCommittedRetiredPreflightRejectsMissingCollectorCustody(
	t *testing.T,
) {
	stateDir, retired, sealed := retiredCommittedFixture(t)

	entries, err := os.ReadDir(stateDir)
	if err != nil {
		t.Fatal(err)
	}

	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "usn-capture-") {
			continue
		}

		name := filepath.Join(stateDir, entry.Name())
		if err := os.Rename(name, name+".missing"); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := VerifyDiscoveredRetiredCommittedGeneration(
		context.Background(),
		stateDir, retired, sealed.DirectoryPath, "m5d-source",
	); err == nil {
		t.Fatal("missing original committed custody was accepted")
	}
}

func TestCommittedRetiredPreflightRejectsChangedRawBytes(t *testing.T) {
	stateDir, retired, sealed := retiredCommittedFixture(t)

	entries, err := os.ReadDir(retired)
	if err != nil {
		t.Fatal(err)
	}

	changed := false
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".jsonl") {
			continue
		}

		path := filepath.Join(retired, entry.Name())
		if err := os.WriteFile(path, []byte("modified\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		changed = true
		break
	}
	if !changed {
		t.Fatal("test fixture has no frozen data file")
	}

	if _, err := VerifyDiscoveredRetiredCommittedGeneration(
		context.Background(),
		stateDir, retired, sealed.DirectoryPath, "m5d-source",
	); err == nil {
		t.Fatal("modified tombstoned bytes were accepted")
	}
}

func TestCommittedRetiredPreflightRejectsChangedSealedBytes(
	t *testing.T,
) {
	stateDir, retired, sealed := retiredCommittedFixture(t)

	if err := os.WriteFile(
		sealed.PayloadPath, []byte("modified"), 0o600,
	); err != nil {
		t.Fatal(err)
	}

	if _, err := VerifyDiscoveredRetiredCommittedGeneration(
		context.Background(),
		stateDir, retired, sealed.DirectoryPath, "m5d-source",
	); err == nil {
		t.Fatal("modified sealed replacement was accepted")
	}
}
