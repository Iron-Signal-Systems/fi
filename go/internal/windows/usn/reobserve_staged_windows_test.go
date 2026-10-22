// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package usn

import (
	"context"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
)

func TestStagedReobservationBoundsConcurrencyAndPreservesBodies(t *testing.T) {
	batch := parallelTestBatch(85)
	var active atomic.Int32
	var peak atomic.Int32
	stageDir := t.TempDir()
	result, stage, err := stageReobservationBatch(
		context.Background(), `C:\FI-Lab`, batch, stageDir, 8, 64, 3,
		func(_ context.Context, _, _ string, id records.NTFSObjectIdentity) (ntfs.Observation, error) {
			concurrent := active.Add(1)
			for {
				old := peak.Load()
				if concurrent <= old || peak.CompareAndSwap(old, concurrent) {
					break
				}
			}
			time.Sleep(3 * time.Millisecond)
			active.Add(-1)
			return ntfs.Observation{ObjectIdentity: id, ObservedAt: "2026-10-19T10:00:00Z"}, nil
		},
		noBackupForParallelTest, noContainmentForParallelTest,
	)
	if err != nil {
		t.Fatal(err)
	}
	if peak.Load() > 3 || peak.Load() < 2 {
		t.Fatalf("peak workers=%d, want 2..3", peak.Load())
	}
	if len(result.Reobservations) != 85 {
		t.Fatalf("observations=%d", len(result.Reobservations))
	}
	path := stage.path
	for i, summary := range result.Reobservations {
		if summary.FileIdentity != batch.Records[i].FileIdentity || summary.Status != ReobservationObserved || summary.Observation == nil {
			t.Fatalf("lost staged result %d: %+v", i, summary)
		}
		if summary.Observation.ObservedAt != "" {
			t.Fatal("large observation unexpectedly retained in RAM")
		}
		original, err := stage.Read(summary.FileIdentity)
		if err != nil {
			t.Fatal(err)
		}
		if original.Observation == nil || original.Observation.ObservedAt != "2026-10-19T10:00:00Z" || original.Observation.ObjectIdentity != summary.FileIdentity {
			t.Fatalf("observation body lost %d: %+v", i, original)
		}
	}
	if err := stage.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("temporary staging file remains: %v", err)
	}
}

func TestStagedReobservationRejectsInvalidLimits(t *testing.T) {
	_, stage, err := stageReobservationBatch(context.Background(), `C:\FI-Lab`, parallelTestBatch(1), t.TempDir(), 8, 0, 32,
		nil, nil, nil)
	if err == nil || stage != nil {
		t.Fatalf("invalid chunk bounds accepted: %v", err)
	}
}

func TestStagedReobservationCorruptionFailsClosed(t *testing.T) {
	batch := parallelTestBatch(1)
	_, stage, err := stageReobservationBatch(
		context.Background(), `C:\FI-Lab`, batch, t.TempDir(), 1, 64, 1,
		func(_ context.Context, _, _ string, id records.NTFSObjectIdentity) (ntfs.Observation, error) {
			return ntfs.Observation{ObjectIdentity: id}, nil
		}, noBackupForParallelTest, noContainmentForParallelTest,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	if _, err := stage.file.WriteAt([]byte("x"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := stage.Read(batch.Records[0].FileIdentity); err == nil {
		t.Fatal("corrupted staged result was accepted")
	}
}
