// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
)

func TestAppendSupportingSourceStartSnapshots(t *testing.T) {
	writer := newSupportingSourceTestWriter(t)

	shares := records.SMBShareSnapshot{}
	local := records.LocalPrincipalSnapshot{}
	supporting := supportingSourceContext{
		CollectorIdentity: records.ProcessIdentityObservation{},
		SMBShareSnapshot:  &shares,
		LocalPrincipals:   &local,
		ObservedSIDs:      newObservedSIDSet(),
	}
	var summary spoolRunSummary

	if err := appendSupportingSourceStart(
		writer,
		"scope-test",
		supporting,
		&summary,
	); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	if summary.CollectorIdentityRecords != 1 {
		t.Fatalf("collector identity records = %d, want 1", summary.CollectorIdentityRecords)
	}
	if summary.SMBShareSnapshotRecords != 1 {
		t.Fatalf("SMB records = %d, want 1", summary.SMBShareSnapshotRecords)
	}
	if summary.LocalPrincipalRecords != 1 {
		t.Fatalf("local principal records = %d, want 1", summary.LocalPrincipalRecords)
	}
	if summary.SupportingSourceErrors != 0 {
		t.Fatalf("supporting source errors = %d, want 0", summary.SupportingSourceErrors)
	}
}

func TestAppendSupportingSourceStartPreservesExplicitErrors(t *testing.T) {
	writer := newSupportingSourceTestWriter(t)

	supporting := supportingSourceContext{
		CollectorIdentity:   records.ProcessIdentityObservation{},
		SMBShareError:       "SMBUnavailable",
		LocalPrincipalError: "LocalIdentityUnavailable",
		ObservedSIDs:        newObservedSIDSet(),
	}
	var summary spoolRunSummary

	if err := appendSupportingSourceStart(
		writer,
		"scope-test",
		supporting,
		&summary,
	); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	if summary.CollectorIdentityRecords != 1 {
		t.Fatalf("collector identity records = %d, want 1", summary.CollectorIdentityRecords)
	}
	if summary.SMBShareSnapshotRecords != 0 {
		t.Fatalf("SMB records = %d, want 0", summary.SMBShareSnapshotRecords)
	}
	if summary.LocalPrincipalRecords != 0 {
		t.Fatalf("local principal records = %d, want 0", summary.LocalPrincipalRecords)
	}
	if summary.SupportingSourceErrors != 2 {
		t.Fatalf("supporting source errors = %d, want 2", summary.SupportingSourceErrors)
	}

	data := readOnlyFinalizedDataFile(t, writer)
	if !strings.Contains(data, `"record_kind":"SupportingSourceCollectionError"`) {
		t.Fatal("supporting-source error record was not written")
	}
	if !strings.Contains(data, `"source":"SMBShareSnapshot"`) {
		t.Fatal("SMB source error was not preserved")
	}
	if !strings.Contains(data, `"source":"LocalPrincipalSnapshot"`) {
		t.Fatal("local identity source error was not preserved")
	}
}

func TestAppendDirectorySourceSnapshotAndError(t *testing.T) {
	t.Run("snapshots", func(t *testing.T) {
		writer := newSupportingSourceTestWriter(t)
		var summary spoolRunSummary

		if err := appendDirectorySource(
			writer,
			"scope-test",
			directorySourceResult{
				Snapshots: []records.DirectoryPrincipalSnapshot{{}, {}},
			},
			&summary,
		); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}

		if summary.DirectoryPrincipalRecords != 2 {
			t.Fatalf("directory records = %d, want 2", summary.DirectoryPrincipalRecords)
		}
		if summary.SupportingSourceErrors != 0 {
			t.Fatalf("supporting source errors = %d, want 0", summary.SupportingSourceErrors)
		}
	})

	t.Run("partial-success-before-error", func(t *testing.T) {
		writer := newSupportingSourceTestWriter(t)
		var summary spoolRunSummary

		if err := appendDirectorySource(
			writer,
			"scope-test",
			directorySourceResult{
				Snapshots: []records.DirectoryPrincipalSnapshot{{}},
				Error:     "DirectoryUnavailable",
			},
			&summary,
		); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}

		if summary.DirectoryPrincipalRecords != 1 {
			t.Fatalf("directory records = %d, want 1", summary.DirectoryPrincipalRecords)
		}
		if summary.SupportingSourceErrors != 1 {
			t.Fatalf("supporting source errors = %d, want 1", summary.SupportingSourceErrors)
		}

		data := readOnlyFinalizedDataFile(t, writer)
		if !strings.Contains(data, `"record_kind":"DirectoryPrincipalSnapshot"`) {
			t.Fatal("completed directory source snapshot was not preserved")
		}
		if !strings.Contains(data, `"source":"DirectoryPrincipalSnapshot"`) {
			t.Fatal("directory source error was not preserved")
		}
	})
}

func newSupportingSourceTestWriter(t *testing.T) *spool.Writer {
	t.Helper()

	writer, err := spool.NewWriter(
		t.TempDir(),
		64,
		spool.CollectorIdentity{
			ExecutablePath:   `C:\test\fi.exe`,
			ExecutableSHA256: strings.Repeat("0", 64),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return writer
}

func readOnlyFinalizedDataFile(t *testing.T, writer *spool.Writer) string {
	t.Helper()

	batches := writer.FinalizedBatches()
	if len(batches) != 1 {
		t.Fatalf("finalized batches = %d, want 1", len(batches))
	}

	path := filepath.Clean(batches[0].DataPath)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
