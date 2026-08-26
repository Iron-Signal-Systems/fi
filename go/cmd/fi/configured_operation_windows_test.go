//go:build windows

package main

import (
	"errors"
	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/operation"
	"testing"
)

func TestRunConfiguredOperationComplete(t *testing.T) {
	t.Setenv("FI_STATE_DIR", t.TempDir())
	record, err := runConfiguredOperation("scope-a", records.OperationBaseline, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if record.Outcome != records.OperationComplete || record.ReasonCode != "" {
		t.Fatalf("unexpected record: %+v", record)
	}
	path, _ := operation.DefaultJournalPath("scope-a")
	entries, err := operation.ReadAll(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Event != operation.JournalStarted || entries[1].Event != operation.JournalFinished {
		t.Fatalf("unexpected journal entries: %+v", entries)
	}
}

func TestRunConfiguredOperationFailed(t *testing.T) {
	t.Setenv("FI_STATE_DIR", t.TempDir())
	record, err := runConfiguredOperation("scope-a", records.OperationUSNCatchUp, func() error { return errors.New("synthetic failure") })
	if err == nil {
		t.Fatal("expected operation body failure")
	}
	if record.Outcome != records.OperationFailed || record.ReasonCode != "USNCatchUpFailed" {
		t.Fatalf("unexpected record: %+v", record)
	}
}

func TestRecoverConfiguredOperations(t *testing.T) {
	t.Setenv("FI_STATE_DIR", t.TempDir())
	path, _ := operation.DefaultJournalPath("scope-a")
	started, err := operation.Start("scope-a", records.OperationReconciliation)
	if err != nil {
		t.Fatal(err)
	}
	if err := operation.AppendStarted(path, started); err != nil {
		t.Fatal(err)
	}
	journalPath, recovered, err := recoverConfiguredOperations("scope-a")
	if err != nil {
		t.Fatal(err)
	}
	if journalPath != path {
		t.Fatalf("journal path=%q want=%q", journalPath, path)
	}
	if len(recovered) != 1 || recovered[0].Outcome != records.OperationInterrupted || recovered[0].ReasonCode != "ProcessRestart" {
		t.Fatalf("unexpected recovery: %+v", recovered)
	}
}
