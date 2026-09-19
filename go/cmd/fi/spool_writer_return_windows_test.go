// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
)

func TestFinalizeSpoolWriterOnReturnClosesAndReportsBatch(
	t *testing.T,
) {
	dir :=
		t.TempDir()

	writer :=
		newReturnFinalizationTestWriter(
			t,
			dir,
		)

	if err :=
		writer.Append(
			"ReturnFinalize",
			"test-scope",
			map[string]string{
				"value": "complete",
			},
		); err != nil {
		t.Fatal(err)
	}

	var batches []spool.FinalizedBatch
	var verified int
	var returnErr error

	finalizeSpoolWriterOnReturn(
		writer,
		&batches,
		&verified,
		&returnErr,
	)

	if returnErr != nil {
		t.Fatalf(
			"return error = %v, want nil",
			returnErr,
		)
	}

	if len(batches) != 1 ||
		verified != 1 {
		t.Fatalf(
			"batches=%d verified=%d, want 1/1",
			len(batches),
			verified,
		)
	}

	verification, err :=
		spool.VerifyManifest(
			batches[0].ManifestPath,
		)
	if err != nil {
		t.Fatal(err)
	}

	if !verification.Verified {
		t.Fatal(
			"deferred-finalization batch did not verify",
		)
	}
}

func TestFinalizeSpoolWriterOnReturnPreservesBodyAndCloseErrors(
	t *testing.T,
) {
	dir :=
		t.TempDir()

	writer :=
		newReturnFinalizationTestWriter(
			t,
			dir,
		)

	if err :=
		writer.Append(
			"ReturnFinalize",
			"test-scope",
			map[string]string{
				"value": "collision",
			},
		); err != nil {
		t.Fatal(err)
	}

	workDir, err :=
		spool.CollectorWorkDir(
			dir,
		)
	if err != nil {
		t.Fatal(err)
	}

	entries, err :=
		os.ReadDir(
			workDir,
		)
	if err != nil {
		t.Fatal(err)
	}

	var batchID string

	for _, entry := range entries {

		name :=
			entry.Name()

		if strings.HasPrefix(
			name,
			"batch-",
		) &&
			strings.HasSuffix(
				name,
				".open",
			) {

			batchID =
				strings.TrimSuffix(
					strings.TrimPrefix(
						name,
						"batch-",
					),
					".open",
				)

			break
		}
	}

	if batchID == "" {
		t.Fatal(
			"could not determine writer batch ID",
		)
	}

	collision :=
		filepath.Join(
			dir,
			"batch-"+
				batchID+
				".jsonl",
		)

	if err :=
		os.WriteFile(
			collision,
			[]byte("collision"),
			0o600,
		); err != nil {
		t.Fatal(err)
	}

	bodyErr :=
		errors.New(
			"body failed",
		)

	returnErr :=
		bodyErr

	var batches []spool.FinalizedBatch
	var verified int

	finalizeSpoolWriterOnReturn(
		writer,
		&batches,
		&verified,
		&returnErr,
	)

	if !errors.Is(
		returnErr,
		bodyErr,
	) {
		t.Fatalf(
			"return error = %v, want original body error retained",
			returnErr,
		)
	}

	if returnErr == bodyErr {
		t.Fatal(
			"Close failure was not joined to body error",
		)
	}

	if len(batches) != 0 ||
		verified != 0 {
		t.Fatalf(
			"batches=%d verified=%d, want 0/0 while collision remains",
			len(batches),
			verified,
		)
	}

	if err :=
		os.Remove(
			collision,
		); err != nil {
		t.Fatal(err)
	}

	// A later retry can still resolve the writer, while the original body
	// failure remains authoritative to the caller.
	finalizeSpoolWriterOnReturn(
		writer,
		&batches,
		&verified,
		&returnErr,
	)

	if !errors.Is(
		returnErr,
		bodyErr,
	) {
		t.Fatalf(
			"original body error was lost after successful retry: %v",
			returnErr,
		)
	}

	if len(batches) != 1 ||
		verified != 1 {
		t.Fatalf(
			"batches=%d verified=%d after retry, want 1/1",
			len(batches),
			verified,
		)
	}
}

func newReturnFinalizationTestWriter(
	t *testing.T,
	dir string,
) *spool.Writer {
	t.Helper()

	writer, err :=
		spool.NewWriter(
			dir,
			1000,
			spool.CollectorIdentity{
				ExecutablePath: "fi-return-finalization-test.exe",
				ExecutableSHA256: strings.Repeat(
					"a",
					64,
				),
			},
		)
	if err != nil {
		t.Fatal(err)
	}

	return writer
}
