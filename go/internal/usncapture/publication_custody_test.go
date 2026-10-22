// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usncapture

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
)

func freezeTestSpool(t *testing.T, dir string) string {
	t.Helper()
	rawRoot := filepath.Join(filepath.Dir(dir), "generation-raw")
	if err := os.Mkdir(rawRoot, 0700); err != nil {
		t.Fatal(err)
	}
	raw := filepath.Join(rawRoot, "generation-m5a-test")
	if err := os.Rename(dir, raw); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestM5AFrozenRawGenerationRetainsSourcePublication(t *testing.T) {
	store, seg, corr, dir, original := sampleSpoolPublication(t, false, false)
	if err := store.BeginSpoolPublication(seg, corr); err != nil {
		t.Fatal(err)
	}
	raw := freezeTestSpool(t, dir)
	// The inspector reports the physical custody path. Windows can return a
	// different spelling from the TempDir path after resolving its directory
	// identity, even though both names refer to the same frozen generation.
	physicalRaw, err := spool.PhysicalSpoolDir(raw)
	if err != nil {
		t.Fatal(err)
	}
	places, err := store.InspectPendingPublicationCustody(seg, corr, dir)
	if err != nil || len(places) != 1 {
		t.Fatalf("places=%v err=%v", places, err)
	}
	if places[0].Kind != PublicationCustodyFrozenRaw || places[0].Directory != physicalRaw ||
		len(places[0].ManifestPaths) != len(original) {
		t.Fatalf("unexpected raw source proof %+v (physicalRaw=%q, original manifests=%d)", places, physicalRaw, len(original))
	}
	expected := make(map[string]bool, len(original))
	for _, originalPath := range original {
		expected[filepath.Base(originalPath)] = true
	}
	for _, manifestPath := range places[0].ManifestPaths {
		name := filepath.Base(manifestPath)
		if filepath.Dir(manifestPath) != physicalRaw || !expected[name] {
			t.Fatalf("frozen source manifest is outside expected custody or is unrelated: %q", manifestPath)
		}
		delete(expected, name)
	}
	if len(expected) != 0 {
		t.Fatalf("missing original manifests after rollover: %v", expected)
	}
	if store.ProcessingCursor().NextUSN != "100" {
		t.Fatal("inspector advanced processing")
	}
	if _, err := store.RecoverPendingSpoolPublication(seg, corr, dir, func([]string) error { return nil }); !errors.Is(err, ErrPublicationPending) {
		t.Fatalf("raw is not an active spool receipt: %v", err)
	}
}

func TestM5AActiveSpoolAndMissingRawRoot(t *testing.T) {
	store, seg, corr, dir, original := sampleSpoolPublication(t, false, false)
	if err := store.BeginSpoolPublication(seg, corr); err != nil {
		t.Fatal(err)
	}
	places, err := store.InspectPendingPublicationCustody(seg, corr, dir)
	if err != nil || len(places) != 1 || places[0].Kind != PublicationCustodyActive ||
		len(places[0].ManifestPaths) != len(original) {
		t.Fatalf("places=%v err=%v", places, err)
	}
	if store.ProcessingCursor().NextUSN != "100" {
		t.Fatal("inspector advanced processing")
	}
}

func TestM5ASealedOrRetiredGenerationMustRemainPending(t *testing.T) {
	store, seg, corr, dir, _ := sampleSpoolPublication(t, false, false)
	if err := store.BeginSpoolPublication(seg, corr); err != nil {
		t.Fatal(err)
	}
	raw := freezeTestSpool(t, dir)
	if err := os.RemoveAll(raw); err != nil {
		t.Fatal(err)
	} // sealed or retired
	if _, err := store.InspectPendingPublicationCustody(seg, corr, dir); !errors.Is(err, ErrPublicationPending) {
		t.Fatalf("missing original FI publication wrongly recovered: %v", err)
	}
	if store.ProcessingCursor().NextUSN != "100" {
		t.Fatal("inspector moved cursor")
	}
}

func TestM5APartialFrozenPublicationIsNotProof(t *testing.T) {
	store, seg, corr, dir, paths := sampleSpoolPublication(t, false, false)
	if err := store.BeginSpoolPublication(seg, corr); err != nil {
		t.Fatal(err)
	}
	raw := freezeTestSpool(t, dir)
	if err := os.Remove(filepath.Join(raw, filepath.Base(paths[len(paths)-1]))); err != nil {
		t.Fatal(err)
	}
	if _, err := store.InspectPendingPublicationCustody(seg, corr, dir); !errors.Is(err, ErrPublicationPending) && !errors.Is(err, ErrCorrupt) {
		t.Fatalf("incomplete raw publication accepted: %v", err)
	}
	if store.ProcessingCursor().NextUSN != "100" {
		t.Fatal("incomplete publication advanced cursor")
	}
}

func TestM5ARejectsRawRootSymlink(t *testing.T) {
	store, seg, corr, dir, _ := sampleSpoolPublication(t, false, false)
	if err := store.BeginSpoolPublication(seg, corr); err != nil {
		t.Fatal(err)
	}
	rawRoot := filepath.Join(filepath.Dir(dir), "generation-raw")
	if err := os.Symlink(t.TempDir(), rawRoot); err != nil {
		t.Skip(err)
	}
	if _, err := store.InspectPendingPublicationCustody(seg, corr, dir); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("reparse raw root accepted: %v", err)
	}
}
