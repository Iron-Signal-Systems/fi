// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package usn

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
)

// Test the actual production count, not just a caller-selected worker count.
func TestEightWorkerProductionConfiguration(t *testing.T) {
	if reobserveWorkerCount != 8 {
		t.Fatalf("production re-observation workers = %d, want 8", reobserveWorkerCount)
	}
}

// Eight tasks must be allowed concurrently. A ninth cannot begin until a
// running task finishes. Results must retain original USN candidate order.
func TestEightWorkerLimitAndOrderedResults(t *testing.T) {
	const jobs = 17
	batch := parallelTestBatch(jobs)
	started := make(chan struct{}, jobs)
	release := make(chan struct{})
	completed := make(chan ReobservationBatch, 1)
	var active atomic.Int32
	var peak atomic.Int32

	go func() {
		completed <- reobserveBatchWithWorkers(
			context.Background(), `C:\FI-Lab`, batch,
			func(_ context.Context, _, _ string, id records.NTFSObjectIdentity) (ntfs.Observation, error) {
				running := active.Add(1)
				for {
					previous := peak.Load()
					if running <= previous || peak.CompareAndSwap(previous, running) {
						break
					}
				}
				started <- struct{}{}
				<-release
				active.Add(-1)
				return ntfs.Observation{ObjectIdentity: id}, nil
			},
			noBackupForParallelTest, noContainmentForParallelTest,
			reobserveWorkerCount,
		)
	}()

	for i := 0; i < 8; i++ {
		select {
		case <-started:
		case <-time.After(10 * time.Second):
			close(release)
			t.Fatal("eight parallel observations did not start")
		}
	}
	select {
	case <-started:
		close(release)
		t.Fatal("more than eight observations started before release")
	default:
	}
	close(release)

	select {
	case result := <-completed:
		if len(result.Reobservations) != jobs {
			t.Fatalf("re-observations = %d, want %d", len(result.Reobservations), jobs)
		}
		for i, observation := range result.Reobservations {
			if observation.FileIdentity != batch.Records[i].FileIdentity ||
				observation.Status != ReobservationObserved ||
				observation.Observation == nil ||
				observation.Observation.ObjectIdentity != batch.Records[i].FileIdentity ||
				len(observation.TriggerUSNs) != 1 ||
				observation.TriggerUSNs[0] != batch.Records[i].USN {
				t.Fatalf("re-observation %d out of order or incomplete: %+v", i, observation)
			}
		}
	case <-time.After(10 * time.Second):
		t.Fatal("eight-worker pool did not finish")
	}
	if peak.Load() != 8 || active.Load() != 0 {
		t.Fatalf("peak=%d active=%d, want peak=8 active=0", peak.Load(), active.Load())
	}
}
