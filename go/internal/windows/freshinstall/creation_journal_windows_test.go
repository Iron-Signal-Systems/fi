// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package freshinstall

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsCreationJournalDurablyRecordsAllEvents(t *testing.T) {
	dir := t.TempDir() // isolated test directory, NEVER a live FI installation
	sink := newWindowsCreationSink(dir)
	creator := &recordingCreator{}
	if err := executeCreation(sink, creator, testCreationIdentity); err != nil {
		_ = sink.Close()
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, nativeCreationJournalName)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	status, err := InspectCreationJournal(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if !status.Complete || status.InDoubt || status.CreationIdentity != testCreationIdentity ||
		status.CreatedSteps != len(creationSteps) || len(creator.steps) != len(creationSteps) {
		t.Fatalf("native disk journal did not roundtrip complete protocol: %+v", status)
	}
}

func TestWindowsCreationJournalRefusesExistingFileWithoutModification(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, nativeCreationJournalName)
	before := []byte("previous installation evidence, never replace")
	if err := os.WriteFile(path, before, 0600); err != nil {
		t.Fatal(err)
	}
	sink := newWindowsCreationSink(dir)
	creator := &recordingCreator{}
	if err := executeCreation(sink, creator, testCreationIdentity); !errors.Is(err, ErrCreationInDoubt) {
		t.Fatalf("existing journal accepted for replacement: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) || len(creator.steps) != 0 {
		t.Fatalf("existing journal modified or native creation started")
	}
}

func TestWindowsCreationJournalNativeMutationFailurePreservesPartialCustody(t *testing.T) {
	dir := t.TempDir()
	sink := newWindowsCreationSink(dir)
	backend := &recordingCreator{failAt: 3}
	if err := executeCreation(sink, backend, testCreationIdentity); !errors.Is(err, ErrCreationInDoubt) {
		t.Fatalf("native partial creation did not fail closed: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, nativeCreationJournalName))
	if err != nil {
		t.Fatal(err)
	}
	status, err := InspectCreationJournal(bytes.NewReader(raw))
	if !errors.Is(err, ErrCreationInDoubt) || !status.InDoubt || status.Complete ||
		status.CreatedSteps != 2 || status.NextStep != creationSteps[2] {
		t.Fatalf("partial native creation was interpreted as complete: %+v %v", status, err)
	}
	second := newWindowsCreationSink(dir)
	retryBackend := &recordingCreator{}
	if err := executeCreation(second, retryBackend, testCreationIdentity); !errors.Is(err, ErrCreationInDoubt) {
		t.Fatalf("existing incomplete journal accepted by new process: %v", err)
	}
	_ = second.Close()
	if len(retryBackend.steps) != 0 {
		t.Fatal("new process restarted an in-doubt installation")
	}
}

func TestWindowsCreationJournalRejectsBadParentAndClosedSink(t *testing.T) {
	testPaths := []string{
		"",
		"relative",
		t.TempDir() + `\no-longer-exists`,
		filepath.VolumeName(t.TempDir()) + `\`,
	}
	for _, path := range testPaths {
		sink := newWindowsCreationSink(path)
		if err := sink.ReserveNew(testInstallID); err == nil {
			_ = sink.Close()
			t.Fatalf("invalid local journal parent accepted: %q", path)
		}
		_ = sink.Close()
	}
	sink := newWindowsCreationSink(t.TempDir())
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	if err := sink.ReserveNew(testInstallID); err == nil {
		t.Fatal("closed native journal sink could reserve a new installation")
	}
}

func TestWindowsCreationJournalRejectsUnsafeFrames(t *testing.T) {
	dir := t.TempDir()
	sink := newWindowsCreationSink(dir)
	if err := sink.ReserveNew(testInstallID); err != nil {
		t.Fatal(err)
	}
	if err := sink.AppendAndSync([]byte("not-a-newline")); err == nil {
		t.Fatal("unterminated journal frame accepted")
	}
	if err := sink.AppendAndSync([]byte("begin\n")); err == nil {
		t.Fatal("poisoned journal allowed a second write")
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsCreationJournalDeniesParentReparseAlias(t *testing.T) {
	dir := t.TempDir()
	actual := filepath.Join(dir, "actual")
	alias := filepath.Join(dir, "alias")
	if err := os.Mkdir(actual, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(actual, alias); err != nil {
		// The Windows runner may not be granted symbolic-link creation rights.
		t.Skipf("Windows symlink privilege unavailable: %v", err)
	}
	sink := newWindowsCreationSink(alias)
	if err := sink.ReserveNew(testInstallID); err == nil {
		_ = sink.Close()
		t.Fatal("reparse parent accepted")
	}
	_ = sink.Close()
	if _, err := os.Stat(filepath.Join(actual, nativeCreationJournalName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("journal written through reparse alias: %v", err)
	}
}
