//go:build freebsd && fi_copy_latency_replay_integration

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// This tests stream selection against FI's already-tested real FIGT sealer,
// receiver, recorder and authenticated loader. It never opens PostgreSQL.
// The production original generation and its private recovery are untouched.
func TestBacklogStreamingSelectedWindowsMatchSignedGeneration(t *testing.T) {
	const count = 32768
	const batchSize = 8192
	source := multiBatchSource
	fixture := t.TempDir()
	for _, part := range []string{"custody", "recorded", "ready",
		filepath.Join("recorded", "sources", source),
		filepath.Join(source, "frozen"), filepath.Join(source, "sealed")} {
		if err := os.MkdirAll(filepath.Join(fixture, part), 0700); err != nil {
			t.Fatal(err)
		}
	}
	signed, batchCount, _, _, _ := writeMultiBatchSignedGeneration(
		t, fixture, "observed", count, batchSize)
	if batchCount != 4 {
		t.Fatalf("expected 4 batches, got %d", batchCount)
	}
	config := GenerationLoadConfig{
		CustodyRoot:      filepath.Join(fixture, "custody"),
		RecordedRoot:     filepath.Join(fixture, "recorded"),
		SourceNamespaces: true, SourceID: source,
		MaxCanonicalBytes: multiBatchMaxGenerationBytes,
		MaxEncodedBytes:   multiBatchMaxGenerationBytes,
		MaxManifestBytes:  1 << 20,
	}
	trustFn := func(got string) (generationTrustBundle, error) {
		if got != source {
			return generationTrustBundle{}, fmt.Errorf("unexpected fixture source %q", got)
		}
		return signed.Trust, nil
	}
	full, err := loadRecordedGenerationWithTrust(config, signed.GenerationID, trustFn)
	if err != nil {
		t.Fatalf("established loader: %v", err)
	}
	defer full.Close()
	limits := BacklogWindowLimits{MaxRecords: 8192, MaxDataBytes: 32 << 20}
	want, err := DescribeBacklogWindows(full, limits)
	if err != nil {
		t.Fatal(err)
	}
	if len(want) != 4 {
		t.Fatalf("expected 4 signed windows, found %d", len(want))
	}

	var progress BacklogStreamProgress
	streamed, err := loadRecordedGenerationSelectedWindowsWithTrust(
		config, signed.GenerationID, limits, 1, 2, trustFn,
		func(p BacklogStreamProgress) { progress = p })
	if err != nil {
		t.Fatalf("streaming loader: %v", err)
	}
	defer streamed.Close()
	got, err := DescribeBacklogWindows(streamed, limits)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatal("different signed window counts")
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("window %d signed descriptor changed", i)
		}
	}
	if streamed.ReceiptSHA256 != full.ReceiptSHA256 ||
		streamed.Receipt.TransferSHA256 != full.Receipt.TransferSHA256 ||
		progress.BatchesSeen != uint64(batchCount) ||
		progress.RecordsSeen != uint64(count) || progress.RetainedBatches != 2 {
		t.Fatalf("stream signed custody identity/count mismatch: progress=%+v", progress)
	}
	files, err := os.ReadDir(streamed.stagedDirectory)
	if err != nil {
		t.Fatal(err)
	}
	retainedFiles := 0
	for _, entry := range files {
		if entry.Name() == generationStageLeaseName {
			continue
		}
		if !entry.Type().IsRegular() {
			t.Fatalf("unexpected stream staging entry %s", entry.Name())
		}
		retainedFiles++
	}
	if retainedFiles != 2 {
		t.Fatalf("stream retained %d files, want 2", retainedFiles)
	}
	for i := range full.Batches {
		a, b := full.Batches[i], streamed.Batches[i]
		if a.BatchID != b.BatchID ||
			a.ManifestSHA256 != b.ManifestSHA256 ||
			a.Manifest.DataSHA256 != b.Manifest.DataSHA256 {
			t.Fatalf("batch %d original manifest identity changed", i)
		}
		if i == 1 || i == 2 {
			if b.DataPath == "" {
				t.Fatalf("selected batch %d not retained", i)
			}
			aa, err := os.ReadFile(a.DataPath)
			if err != nil {
				t.Fatal(err)
			}
			bb, err := os.ReadFile(b.DataPath)
			if err != nil {
				t.Fatal(err)
			}
			if string(aa) != string(bb) {
				t.Fatalf("selected batch %d bytes differ", i)
			}
		} else if b.DataPath != "" {
			t.Fatalf("skipped batch %d retained data unexpectedly", i)
		}
	}
	// A selected retained window must work with the unchanged deterministic
	// private MaterializeBacklogWindow format and original signed chain.
	root := privateBacklogTestRoot(t)
	if _, err := MaterializeBacklogWindow(context.Background(), streamed, limits, 1, root); err != nil {
		t.Fatal(err)
	}
	if err := VerifyMaterializedBacklogWindow(context.Background(), streamed, limits, 1, root); err != nil {
		t.Fatal(err)
	}
	t.Log("PASS: whole signed transfer authenticated in one streamed pass; 2/4 data batches retained; identical signed window hashes; private stage copy verified; no PostgreSQL writes")
}
