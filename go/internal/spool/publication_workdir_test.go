// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package spool

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWriterBuildsOutsidePublishedSpool(
	t *testing.T,
) {
	spoolDir :=
		t.TempDir()

	writer :=
		newPublicationWorkdirTestWriter(
			t,
			spoolDir,
		)

	writer.targetBatchBytes =
		1024 * 1024

	if err :=
		writer.Append(
			"test",
			"scope",
			map[string]string{
				"value": "one",
			},
		); err != nil {
		t.Fatal(err)
	}

	spoolEntries, err :=
		os.ReadDir(
			writer.dir,
		)
	if err != nil {
		t.Fatal(err)
	}

	if len(spoolEntries) != 0 {
		t.Fatalf(
			"active spool contains %d entries while batch is open; want 0",
			len(spoolEntries),
		)
	}

	workEntries, err :=
		os.ReadDir(
			writer.workDir,
		)
	if err != nil {
		t.Fatal(err)
	}

	if len(workEntries) != 1 {
		t.Fatalf(
			"collector work directory contains %d entries; want 1 open batch",
			len(workEntries),
		)
	}

	if filepath.Ext(
		workEntries[0].Name(),
	) != ".open" {
		t.Fatalf(
			"collector work artifact = %q, want .open",
			workEntries[0].Name(),
		)
	}

	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	spoolEntries, err =
		os.ReadDir(
			writer.dir,
		)
	if err != nil {
		t.Fatal(err)
	}

	if len(spoolEntries) != 2 {
		t.Fatalf(
			"published spool contains %d entries after Close; want 2",
			len(spoolEntries),
		)
	}

	workEntries, err =
		os.ReadDir(
			writer.workDir,
		)
	if err != nil {
		t.Fatal(err)
	}

	if len(workEntries) != 0 {
		t.Fatalf(
			"collector work directory contains %d entries after publication; want 0",
			len(workEntries),
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
			"published batch did not independently verify",
		)
	}
}

func TestOpenWriterDoesNotHoldPublicationBoundary(
	t *testing.T,
) {
	spoolDir :=
		t.TempDir()

	writer :=
		newPublicationWorkdirTestWriter(
			t,
			spoolDir,
		)

	writer.targetBatchBytes =
		1024 * 1024

	if err :=
		writer.Append(
			"test",
			"scope",
			map[string]string{
				"value": "one",
			},
		); err != nil {
		t.Fatal(err)
	}

	type boundaryResult struct {
		guard io.Closer
		err   error
	}

	result :=
		make(
			chan boundaryResult,
			1,
		)

	go func() {
		guard, err :=
			AcquirePublishBoundary()

		result <- boundaryResult{
			guard: guard,
			err:   err,
		}
	}()

	select {
	case acquired :=
		<-result:

		if acquired.err != nil {
			t.Fatal(
				acquired.err,
			)
		}

		if acquired.guard == nil {
			t.Fatal(
				"publication boundary returned nil guard",
			)
		}

		if err :=
			acquired.guard.Close(); err != nil {
			t.Fatal(err)
		}

	case <-time.After(
		2 * time.Second,
	):
		t.Fatal(
			"open collector batch still holds publication boundary",
		)
	}

	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPublicationCollisionDoesNotPartiallyPublishData(
	t *testing.T,
) {
	spoolDir :=
		t.TempDir()

	writer :=
		newPublicationWorkdirTestWriter(
			t,
			spoolDir,
		)

	writer.targetBatchBytes =
		1024 * 1024

	if err :=
		writer.Append(
			"test",
			"scope",
			map[string]string{
				"value": "one",
			},
		); err != nil {
		t.Fatal(err)
	}

	batchID :=
		writer.batchID

	manifestPath :=
		filepath.Join(
			writer.dir,
			"batch-"+
				batchID+
				".manifest.json",
		)

	if err :=
		os.WriteFile(
			manifestPath,
			[]byte("collision"),
			0o600,
		); err != nil {
		t.Fatal(err)
	}

	err :=
		writer.Close()

	if err == nil {
		t.Fatal(
			"Close succeeded despite publication collision",
		)
	}

	dataPath :=
		filepath.Join(
			writer.dir,
			"batch-"+
				batchID+
				".jsonl",
		)

	if _, statErr :=
		os.Stat(
			dataPath,
		); !os.IsNotExist(statErr) {
		t.Fatalf(
			"batch data partially published despite preflight collision: %v",
			statErr,
		)
	}

	workDataPath :=
		filepath.Join(
			writer.workDir,
			"batch-"+
				batchID+
				".jsonl",
		)

	workManifestPath :=
		filepath.Join(
			writer.workDir,
			"batch-"+
				batchID+
				".manifest.json",
		)

	if _, statErr :=
		os.Stat(
			workDataPath,
		); statErr != nil {
		t.Fatalf(
			"prepared work data missing after failed publication: %v",
			statErr,
		)
	}

	if _, statErr :=
		os.Stat(
			workManifestPath,
		); statErr != nil {
		t.Fatalf(
			"prepared work manifest missing after failed publication: %v",
			statErr,
		)
	}
}

func newPublicationWorkdirTestWriter(
	t *testing.T,
	spoolDir string,
) *Writer {
	t.Helper()

	writer, err :=
		NewWriter(
			spoolDir,
			DefaultBatchSize,
			CollectorIdentity{
				ExecutablePath: `C:\Program Files\FI\fi.exe`,
				ExecutableSHA256: strings.Repeat(
					"d",
					64,
				),
			},
		)

	if err != nil {
		t.Fatal(err)
	}

	return writer
}
