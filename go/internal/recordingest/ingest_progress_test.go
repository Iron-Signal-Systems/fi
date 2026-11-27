// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"time"
)

func progressFixture(out *bytes.Buffer, started time.Time) *ingestProgress {
	return newIngestProgress(out, "source.test", "generation-1", 3, 3072,
		started, &ingestStageProfile{}, &ntfsStageTimingCounters{},
		newContentHashCopyState(), newUSNChangeCopyState(), newACECopyState())
}

func TestIngestProgressSnapshotsAreUncommitted(t *testing.T) {
	var out bytes.Buffer
	started := time.Now().Add(-30 * time.Second)
	p := progressFixture(&out, started)
	p.profile.Read = 200 * time.Millisecond
	p.ntfs.Identity = 12 * time.Millisecond
	p.hash.duration = 60 * time.Millisecond
	p.hash.latency.observe(60 * time.Millisecond)
	p.publish(1024)
	p.emit("inflight", time.Now())
	got := out.String()
	for _, want := range []string{
		"source=source.test", "generation=generation-1", "status=inflight",
		"batches_completed=0/3", "records_read=1024/3072", "committed=0",
		"read=200ms", "ntfs_identity=12ms", "tracked_copy=60ms",
		"tracked_copy_calls=1", "snapshot_age=", "tx_age=",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %s", want, got)
		}
	}
	if strings.Contains(got, "records_committed=1024") {
		t.Fatal("uncommitted rows mislabeled as committed")
	}
}

func TestIngestProgressBatchCompletionAndFailure(t *testing.T) {
	var out bytes.Buffer
	p := progressFixture(&out, time.Now().Add(-2*time.Second))
	p.completeBatch(512)
	p.publish(16)
	p.emit("uncommitted", time.Now())
	got := out.String()
	for _, want := range []string{"batches_completed=1/3", "records_read=528/3072", "status=uncommitted", "committed=0"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %s", want, got)
		}
	}
}

// A background reporter can only access immutable snapshots. Run under
// go test -race to validate publication and cancellation behavior.
func TestIngestProgressConcurrentReportAndStop(t *testing.T) {
	var out lockedBuffer
	p := newIngestProgress(&out, "source.test", "generation-1", 1, 100,
		time.Now(), &ingestStageProfile{}, &ntfsStageTimingCounters{},
		newContentHashCopyState(), newUSNChangeCopyState(), newACECopyState())
	p.interval = time.Millisecond
	p.start()
	for i := 0; i < 100; i++ {
		p.publish(int64(i))
	}
	time.Sleep(5 * time.Millisecond)
	p.stop()
	p.stop() // Idempotent, no goroutine leak or double close.
	p.emit("inflight", time.Now())
	if !strings.Contains(out.String(), "status=inflight") {
		t.Fatal("progress reporter produced no output")
	}
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}
func (b *lockedBuffer) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.b.String() }

// Prove a timer heartbeat actually emits while ingestion is not publishing
// new counters, as it would during a long blocking PostgreSQL call.
func TestIngestProgressHeartbeatDuringStall(t *testing.T) {
	out := &notifyingWriter{wrote: make(chan struct{}, 1)}
	p := newIngestProgress(out, "source.test", "generation-1", 1, 100,
		time.Now(), &ingestStageProfile{}, &ntfsStageTimingCounters{},
		newContentHashCopyState(), newUSNChangeCopyState(), newACECopyState())
	p.interval = 2 * time.Millisecond
	p.start()
	select {
	case <-out.wrote:
	case <-time.After(time.Second):
		p.stop()
		t.Fatal("no heartbeat during stalled ingest")
	}
	p.stop()
	if !strings.Contains(out.String(), "status=inflight") {
		t.Fatal("heartbeat did not include an in-flight status")
	}
}

type notifyingWriter struct {
	lockedBuffer
	wrote chan struct{}
}

func (w *notifyingWriter) Write(b []byte) (int, error) {
	n, err := w.lockedBuffer.Write(b)
	select {
	case w.wrote <- struct{}{}:
	default:
	}
	return n, err
}
