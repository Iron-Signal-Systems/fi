// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package operation

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func TestAppendStartedAndFinishedRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operations.jsonl")
	started := Started{
		OperationID: "op-0123456789abcdef0123456789abcdef",
		ScopeID:     "manual-test",
		Kind:        records.OperationUSNRead,
		StartedAt:   "2026-08-22T17:20:00.000000000Z",
	}
	finished := records.OperationRecord{
		OperationID: started.OperationID,
		ScopeID:     started.ScopeID,
		Kind:        started.Kind,
		StartedAt:   started.StartedAt,
		FinishedAt:  "2026-08-22T17:20:01.000000000Z",
		Outcome:     records.OperationComplete,
	}

	if err := AppendStarted(path, started); err != nil {
		t.Fatal(err)
	}
	if err := AppendFinished(path, finished); err != nil {
		t.Fatal(err)
	}

	values, err := ReadAll(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 2 {
		t.Fatalf("got %d entries, want 2", len(values))
	}
	if values[0].Event != JournalStarted {
		t.Fatalf("first event = %q, want %q", values[0].Event, JournalStarted)
	}
	if values[1].Event != JournalFinished {
		t.Fatalf("second event = %q, want %q", values[1].Event, JournalFinished)
	}
	if values[0].OperationID != values[1].OperationID {
		t.Fatal("operation lifecycle entries do not share operation id")
	}
}

func TestStartedEntryIsDurableWithoutFinishedEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operations.jsonl")
	started := Started{
		OperationID: "op-fedcba9876543210fedcba9876543210",
		ScopeID:     "manual-test",
		Kind:        records.OperationReObservation,
		StartedAt:   "2026-08-22T17:21:00.000000000Z",
	}

	if err := AppendStarted(path, started); err != nil {
		t.Fatal(err)
	}

	values, err := ReadAll(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 1 {
		t.Fatalf("got %d entries, want 1", len(values))
	}
	if values[0].Event != JournalStarted {
		t.Fatalf("event = %q, want %q", values[0].Event, JournalStarted)
	}
	if values[0].OperationID != started.OperationID {
		t.Fatalf("operation id = %q, want %q", values[0].OperationID, started.OperationID)
	}
}

func TestReadAllAcceptsLegacyTerminalRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operations.jsonl")
	legacy := `{"operation_id":"op-0123456789abcdef0123456789abcdef","scope_id":"manual-test","kind":"USNRead","started_at":"2026-08-22T17:20:00.000000000Z","finished_at":"2026-08-22T17:20:01.000000000Z","outcome":"Complete"}` + "\n"

	if err := os.WriteFile(path, []byte(legacy), 0600); err != nil {
		t.Fatal(err)
	}

	values, err := ReadAll(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 1 {
		t.Fatalf("got %d entries, want 1", len(values))
	}
	if values[0].Event != JournalFinished {
		t.Fatalf("event = %q, want %q", values[0].Event, JournalFinished)
	}
}

func TestRecoverInterruptedAppendsTerminalEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operations.jsonl")
	started := Started{
		OperationID: "op-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ScopeID:     "manual-test",
		Kind:        records.OperationUSNRead,
		StartedAt:   "2026-08-22T17:22:00.000000000Z",
	}

	if err := AppendStarted(path, started); err != nil {
		t.Fatal(err)
	}

	recovered, err := RecoverInterrupted(path, "manual-test")
	if err != nil {
		t.Fatal(err)
	}
	if len(recovered) != 1 {
		t.Fatalf("got %d recovered operations, want 1", len(recovered))
	}
	if recovered[0].OperationID != started.OperationID {
		t.Fatalf("recovered operation id = %q, want %q", recovered[0].OperationID, started.OperationID)
	}
	if recovered[0].Outcome != records.OperationInterrupted {
		t.Fatalf("outcome = %q, want %q", recovered[0].Outcome, records.OperationInterrupted)
	}
	if recovered[0].ReasonCode != "ProcessRestart" {
		t.Fatalf("reason = %q, want ProcessRestart", recovered[0].ReasonCode)
	}

	entries, err := ReadAll(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d journal entries, want 2", len(entries))
	}
	if entries[0].Event != JournalStarted || entries[1].Event != JournalFinished {
		t.Fatalf("unexpected lifecycle order: %q then %q", entries[0].Event, entries[1].Event)
	}
	if entries[1].Outcome != records.OperationInterrupted || entries[1].ReasonCode != "ProcessRestart" {
		t.Fatalf("unexpected recovered terminal entry: outcome=%q reason=%q", entries[1].Outcome, entries[1].ReasonCode)
	}
}

func TestRecoverInterruptedIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operations.jsonl")
	started := Started{
		OperationID: "op-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		ScopeID:     "manual-test",
		Kind:        records.OperationReObservation,
		StartedAt:   "2026-08-22T17:23:00.000000000Z",
	}

	if err := AppendStarted(path, started); err != nil {
		t.Fatal(err)
	}
	if _, err := RecoverInterrupted(path, "manual-test"); err != nil {
		t.Fatal(err)
	}

	recovered, err := RecoverInterrupted(path, "manual-test")
	if err != nil {
		t.Fatal(err)
	}
	if len(recovered) != 0 {
		t.Fatalf("second recovery returned %d operations, want 0", len(recovered))
	}

	entries, err := ReadAll(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries after second recovery, want 2", len(entries))
	}
}

func TestRecoverInterruptedLeavesCompletedOperationAlone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operations.jsonl")
	started := Started{
		OperationID: "op-cccccccccccccccccccccccccccccccc",
		ScopeID:     "manual-test",
		Kind:        records.OperationUSNRead,
		StartedAt:   "2026-08-22T17:24:00.000000000Z",
	}
	finished := records.OperationRecord{
		OperationID: started.OperationID,
		ScopeID:     started.ScopeID,
		Kind:        started.Kind,
		StartedAt:   started.StartedAt,
		FinishedAt:  "2026-08-22T17:24:01.000000000Z",
		Outcome:     records.OperationComplete,
	}

	if err := AppendStarted(path, started); err != nil {
		t.Fatal(err)
	}
	if err := AppendFinished(path, finished); err != nil {
		t.Fatal(err)
	}

	recovered, err := RecoverInterrupted(path, "manual-test")
	if err != nil {
		t.Fatal(err)
	}
	if len(recovered) != 0 {
		t.Fatalf("recovered %d completed operations, want 0", len(recovered))
	}
}

func TestRecoverInterruptedMissingJournalIsNoOp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.jsonl")
	recovered, err := RecoverInterrupted(path, "manual-test")
	if err != nil {
		t.Fatal(err)
	}
	if len(recovered) != 0 {
		t.Fatalf("recovered %d operations from missing journal, want 0", len(recovered))
	}
}
