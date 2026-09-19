// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package spool

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriterCloseDoesNotFalseSucceedAfterPublicationCollision(
	t *testing.T,
) {
	dir :=
		t.TempDir()

	writer :=
		newWriterRetryTestWriter(
			t,
			dir,
		)

	if err :=
		writer.Append(
			"RetryRecord",
			"retry-scope",
			map[string]string{
				"value": "one",
			},
		); err != nil {
		t.Fatal(err)
	}

	collision :=
		filepath.Join(
			dir,
			"batch-"+
				writer.batchID+
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

	if err :=
		writer.Close(); err == nil {
		t.Fatal(
			"first Close unexpectedly succeeded with publication collision",
		)
	}

	if writer.pending == nil {
		t.Fatal(
			"writer lost pending batch after failed Close",
		)
	}

	if writer.closed {
		t.Fatal(
			"writer marked closed after failed finalization",
		)
	}

	if err :=
		writer.Close(); err == nil {
		t.Fatal(
			"second Close falsely succeeded while collision remained",
		)
	}

	if err :=
		writer.Append(
			"RetryRecord",
			"retry-scope",
			map[string]string{
				"value": "duplicate-attempt",
			},
		); !errors.Is(
		err,
		ErrWriterPendingFinalization,
	) {
		t.Fatalf(
			"Append error = %v, want ErrWriterPendingFinalization",
			err,
		)
	}

	if err :=
		os.Remove(
			collision,
		); err != nil {
		t.Fatal(err)
	}

	if err :=
		writer.Close(); err != nil {
		t.Fatalf(
			"retry Close after removing collision: %v",
			err,
		)
	}

	assertWriterRetryFinalizedOnce(
		t,
		writer,
	)
}

func TestWriterCloseRetriesManifestPreparation(
	t *testing.T,
) {
	dir :=
		t.TempDir()

	writer :=
		newWriterRetryTestWriter(
			t,
			dir,
		)

	if err :=
		writer.Append(
			"RetryRecord",
			"retry-scope",
			map[string]string{
				"value": "manifest",
			},
		); err != nil {
		t.Fatal(err)
	}

	blocker :=
		filepath.Join(
			writer.workDir,
			"batch-"+
				writer.batchID+
				".manifest.json.open",
		)

	if err :=
		os.WriteFile(
			blocker,
			[]byte("block"),
			0o600,
		); err != nil {
		t.Fatal(err)
	}

	if err :=
		writer.Close(); err == nil {
		t.Fatal(
			"Close unexpectedly succeeded with manifest-open collision",
		)
	}

	if writer.pending == nil {
		t.Fatal(
			"writer lost pending batch after manifest preparation failure",
		)
	}

	if err :=
		writer.Close(); err == nil {
		t.Fatal(
			"retry Close falsely succeeded while manifest-open collision remained",
		)
	}

	if err :=
		os.Remove(
			blocker,
		); err != nil {
		t.Fatal(err)
	}

	if err :=
		writer.Close(); err != nil {
		t.Fatalf(
			"retry Close after manifest blocker removal: %v",
			err,
		)
	}

	assertWriterRetryFinalizedOnce(
		t,
		writer,
	)
}

func TestWriterCloseRepairsActiveDataWorkManifestState(
	t *testing.T,
) {
	dir :=
		t.TempDir()

	writer :=
		prepareWriterRetryWorkPair(
			t,
			dir,
		)

	pending :=
		writer.pending

	if err :=
		durableRename(
			pending.workDataPath,
			filepath.Join(
				dir,
				pending.dataName,
			),
		); err != nil {
		t.Fatal(err)
	}

	if err :=
		writer.Close(); err != nil {
		t.Fatalf(
			"Close did not repair active-data/work-manifest state: %v",
			err,
		)
	}

	assertWriterRetryFinalizedOnce(
		t,
		writer,
	)
}

func TestWriterCloseAcceptsVerifiedAlreadyPublishedPair(
	t *testing.T,
) {
	dir :=
		t.TempDir()

	writer :=
		prepareWriterRetryWorkPair(
			t,
			dir,
		)

	pending :=
		writer.pending

	activeData :=
		filepath.Join(
			dir,
			pending.dataName,
		)

	activeManifest :=
		filepath.Join(
			dir,
			pending.manifestName,
		)

	if err :=
		durableRename(
			pending.workDataPath,
			activeData,
		); err != nil {
		t.Fatal(err)
	}

	if err :=
		durableRename(
			pending.workManifestPath,
			activeManifest,
		); err != nil {
		t.Fatal(err)
	}

	if err :=
		writer.Close(); err != nil {
		t.Fatalf(
			"Close did not accept verified already-published pair: %v",
			err,
		)
	}

	assertWriterRetryFinalizedOnce(
		t,
		writer,
	)

	if err :=
		writer.Close(); err != nil {
		t.Fatalf(
			"Close after completed retry = %v, want nil",
			err,
		)
	}

	if got :=
		len(
			writer.FinalizedBatches(),
		); got != 1 {
		t.Fatalf(
			"finalized batches after repeated Close = %d, want 1",
			got,
		)
	}
}

func prepareWriterRetryWorkPair(
	t *testing.T,
	dir string,
) *Writer {
	t.Helper()

	writer :=
		newWriterRetryTestWriter(
			t,
			dir,
		)

	if err :=
		writer.Append(
			"RetryRecord",
			"retry-scope",
			map[string]string{
				"value": "prepared",
			},
		); err != nil {
		t.Fatal(err)
	}

	collision :=
		filepath.Join(
			dir,
			"batch-"+
				writer.batchID+
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

	if err :=
		writer.Close(); err == nil {
		t.Fatal(
			"Close unexpectedly succeeded while preparing retry work pair",
		)
	}

	if writer.pending == nil ||
		!writer.pending.dataPrepared ||
		!writer.pending.manifestPrepared {
		t.Fatal(
			"writer did not retain fully prepared retry state",
		)
	}

	if err :=
		os.Remove(
			collision,
		); err != nil {
		t.Fatal(err)
	}

	return writer
}

func newWriterRetryTestWriter(
	t *testing.T,
	dir string,
) *Writer {
	t.Helper()

	writer, err :=
		NewWriter(
			dir,
			1000,
			CollectorIdentity{
				ExecutablePath: "fi-retry-test.exe",
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

func assertWriterRetryFinalizedOnce(
	t *testing.T,
	writer *Writer,
) {
	t.Helper()

	if writer.pending != nil {
		t.Fatal(
			"writer retained pending batch after successful retry",
		)
	}

	if !writer.closed {
		t.Fatal(
			"writer did not enter closed state after successful Close",
		)
	}

	batches :=
		writer.FinalizedBatches()

	if len(batches) != 1 {
		t.Fatalf(
			"finalized batches = %d, want 1",
			len(batches),
		)
	}

	verification, err :=
		VerifyManifest(
			batches[0].ManifestPath,
		)
	if err != nil {
		t.Fatal(err)
	}

	if !verification.Verified {
		t.Fatal(
			"retried finalized batch did not verify",
		)
	}
}
