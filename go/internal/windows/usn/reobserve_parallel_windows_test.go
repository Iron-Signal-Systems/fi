// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package usn

import (
	"context"
	"errors"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
)

func parallelTestBatch(count int) records.USNReadBatch {
	batch := records.USNReadBatch{ScopeID: "scope-parallel"}
	for index := 0; index < count; index++ {
		batch.Records = append(batch.Records, records.USNChangeObservation{
			FileIdentity: records.NTFSObjectIdentity{
				MethodVersion:       ntfs.IdentityMethodVersion,
				FileReferenceNumber: strconv.Itoa(index + 70000),
				SequenceNumber:      "1",
			},
			USN: strconv.Itoa(1000 + index),
		})
	}
	return batch
}

func noBackupForParallelTest(context.Context, string, records.NTFSObjectIdentity) (ntfs.Observation, error) {
	return ntfs.Observation{}, errors.New("unexpected backup authority request")
}
func noContainmentForParallelTest(context.Context, string, records.NTFSObjectIdentity) (ContainmentResult, error) {
	return ContainmentUnavailable, errors.New("unexpected containment request")
}

func TestParallelReobservationRunsFourBoundedWorkers(t *testing.T) {
	batch := parallelTestBatch(9)
	started := make(chan struct{}, 9)
	release := make(chan struct{})
	var concurrent atomic.Int32
	var peak atomic.Int32
	results := make(chan ReobservationBatch, 1)

	go func() {
		results <- reobserveBatchWithWorkers(
			context.Background(), `C:\FI-Lab`, batch,
			func(_ context.Context, _, _ string, id records.NTFSObjectIdentity) (ntfs.Observation, error) {
				active := concurrent.Add(1)
				for {
					old := peak.Load()
					if active <= old || peak.CompareAndSwap(old, active) {
						break
					}
				}
				started <- struct{}{}
				<-release
				concurrent.Add(-1)
				return ntfs.Observation{ObjectIdentity: id}, nil
			},
			noBackupForParallelTest, noContainmentForParallelTest, 4,
		)
	}()

	for index := 0; index < 4; index++ {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			close(release)
			t.Fatal("did not run four objects concurrently")
		}
	}
	select {
	case <-started:
		close(release)
		t.Fatal("more than four objects active before workers were released")
	default:
	}
	close(release)
	select {
	case result := <-results:
		if len(result.Reobservations) != len(batch.Records) {
			t.Fatalf("results=%d want=%d", len(result.Reobservations), len(batch.Records))
		}
		for index, observed := range result.Reobservations {
			if observed.FileIdentity != batch.Records[index].FileIdentity ||
				observed.TriggerUSNs[0] != batch.Records[index].USN ||
				observed.Status != ReobservationObserved {
				t.Fatalf("result %d out of order or failed: %+v", index, observed)
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("worker pool did not drain")
	}
	if peak.Load() != 4 || concurrent.Load() != 0 {
		t.Fatalf("peak=%d active=%d", peak.Load(), concurrent.Load())
	}
}

func TestParallelReobservationPreservesOrderWhenFinishingOutOfOrder(t *testing.T) {
	batch := parallelTestBatch(12)
	result := reobserveBatchWithWorkers(
		context.Background(), `C:\FI-Lab`, batch,
		func(_ context.Context, _, _ string, id records.NTFSObjectIdentity) (ntfs.Observation, error) {
			n, _ := strconv.Atoi(id.FileReferenceNumber)
			time.Sleep(time.Duration(12-(n-70000)) * time.Millisecond)
			return ntfs.Observation{ObjectIdentity: id}, nil
		},
		noBackupForParallelTest, noContainmentForParallelTest, 4,
	)
	for index, observation := range result.Reobservations {
		if observation.FileIdentity != batch.Records[index].FileIdentity ||
			observation.Status != ReobservationObserved ||
			observation.Observation == nil ||
			observation.Observation.ObjectIdentity != batch.Records[index].FileIdentity {
			t.Fatalf("result %d mismatch: %+v", index, observation)
		}
	}
}

func TestParallelReobservationCancellationDoesNotCollect(t *testing.T) {
	batch := parallelTestBatch(8)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var calls atomic.Int32
	result := reobserveBatchWithWorkers(
		ctx, `C:\FI-Lab`, batch,
		func(context.Context, string, string, records.NTFSObjectIdentity) (ntfs.Observation, error) {
			calls.Add(1)
			return ntfs.Observation{}, errors.New("collection after cancellation")
		},
		noBackupForParallelTest, noContainmentForParallelTest, 4,
	)
	if calls.Load() != 0 || len(result.Reobservations) != len(batch.Records) {
		t.Fatalf("calls=%d results=%d", calls.Load(), len(result.Reobservations))
	}
	for index, item := range result.Reobservations {
		if item.Status != ReobservationError || item.ReasonCode != "ContextCanceled" ||
			item.FileIdentity != batch.Records[index].FileIdentity {
			t.Fatalf("canceled result %d invalid: %+v", index, item)
		}
	}
}

func TestParallelReobservationBackupAuthorityOnlyOnOpenDenied(t *testing.T) {
	batch := parallelTestBatch(8)
	var backupCalls atomic.Int32
	var containmentCalls atomic.Int32
	result := reobserveBatchWithWorkers(
		context.Background(), `C:\FI-Lab`, batch,
		func(_ context.Context, _, _ string, id records.NTFSObjectIdentity) (ntfs.Observation, error) {
			n, _ := strconv.Atoi(id.FileReferenceNumber)
			if n%2 == 0 {
				return ntfs.Observation{}, openFileByIDAccessDenied()
			}
			return ntfs.Observation{}, &ntfs.Error{Stage: ntfs.StageMetadata, Op: "ReadDescriptor", Err: errors.New("metadata error")}
		},
		func(_ context.Context, _ string, id records.NTFSObjectIdentity) (ntfs.Observation, error) {
			backupCalls.Add(1)
			return ntfs.Observation{ObjectIdentity: id}, nil
		},
		func(context.Context, string, records.NTFSObjectIdentity) (ContainmentResult, error) {
			containmentCalls.Add(1)
			return ContainmentUnavailable, errors.New("must not inspect containment after successful backup")
		}, 4,
	)
	if backupCalls.Load() != 4 || containmentCalls.Load() != 0 {
		t.Fatalf("backup=%d containment=%d", backupCalls.Load(), containmentCalls.Load())
	}
	for index, item := range result.Reobservations {
		if index%2 == 0 && item.Status != ReobservationObserved {
			t.Fatalf("open denied object %d did not use backup: %+v", index, item)
		}
		if index%2 == 1 && item.Status != ReobservationError {
			t.Fatalf("metadata failure %d improperly escalated: %+v", index, item)
		}
	}
}
