// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

const (
	ingestProgressInterval         = 30 * time.Second
	ingestProgressRecordCheckpoint = 1024
)

type ingestProgressContextKey struct{}

// ingestProgressSnapshot is immutable once published. The ingest goroutine
// alone reads the existing timing counters. The heartbeat goroutine reads
// ONLY this atomic snapshot, so it cannot race with PostgreSQL operations.
// Counts are attempted/read records, never committed or published records.
type ingestProgressSnapshot struct {
	capturedAt       time.Time
	batchesCompleted int
	recordsRead      int64
	read             time.Duration
	batchHash        time.Duration
	prepare          time.Duration
	sourceSQL        time.Duration
	projection       time.Duration
	identity         time.Duration
	trackedCOPY      time.Duration
	trackedCOPYCalls int64
	copyTop          string // Sorted top-three CopyFrom elapsed totals.
}

// ingestProgress is scoped to one relational generation transaction.
// It introduces no database calls, mutations, locks in the ingest path, or
// per-record logging. Only the ingest goroutine mutates the non-atomic fields.
type ingestProgress struct {
	sourceID           string
	generationID       string
	batchesTotal       int
	recordsTotal       int64
	transactionStarted time.Time
	interval           time.Duration
	out                io.Writer
	snapshot           atomic.Pointer[ingestProgressSnapshot]
	profile            *ingestStageProfile
	ntfs               *ntfsStageTimingCounters
	hash               *contentHashCopyState
	usn                *usnChangeCopyState
	ace                *aceCopyState
	copyMetrics        *ingestCopyMetrics
	batchesCompleted   int
	recordsCompleted   int64
	stopCh             chan struct{}
	finishedCh         chan struct{}
	stopOnce           sync.Once
}

func newIngestProgress(out io.Writer, sourceID, generationID string, batches int, records int64,
	started time.Time, profile *ingestStageProfile, ntfs *ntfsStageTimingCounters,
	hash *contentHashCopyState, usn *usnChangeCopyState, ace *aceCopyState,
) *ingestProgress {
	p := &ingestProgress{
		sourceID: sourceID, generationID: generationID,
		batchesTotal: batches, recordsTotal: records,
		transactionStarted: started, interval: ingestProgressInterval,
		out: out, profile: profile, ntfs: ntfs, hash: hash, usn: usn, ace: ace,
	}
	p.publish(0)
	return p
}

// publish is called only by the ingest goroutine at bounded checkpoints.
// inBatch counts input records read in the current batch, NOT committed rows.
// All duration values may overlap; they must not be added to infer elapsed time.
func (p *ingestProgress) publish(inBatch int64) {
	if p == nil {
		return
	}
	s := &ingestProgressSnapshot{
		capturedAt:       time.Now(),
		batchesCompleted: p.batchesCompleted,
		recordsRead:      p.recordsCompleted + inBatch,
		read:             p.profile.Read,
		batchHash:        p.profile.BatchHash,
		prepare:          p.profile.Prepare,
		sourceSQL:        p.profile.SourceSQL,
		projection:       p.profile.Projection,
		identity:         p.ntfs.Identity,
	}
	s.trackedCOPY = p.profile.BatchBulk.Copy + p.profile.CoverageBulk.Copy +
		p.profile.SecurityBulk.SourceCopy + p.profile.SecurityBulk.EventCopy +
		p.profile.SecurityBulk.ScopeCopy + p.profile.SecurityBulk.FieldCopy +
		p.hash.duration + p.usn.duration + p.ace.duration
	s.trackedCOPYCalls = int64(p.profile.BatchBulk.Copies) +
		p.profile.SecurityBulk.SourceLatency.Calls + p.profile.SecurityBulk.EventLatency.Calls +
		p.profile.SecurityBulk.ScopeLatency.Calls + p.profile.SecurityBulk.FieldLatency.Calls +
		p.ntfs.FileCopyLatency.Calls + p.ntfs.MetadataCopyLatency.Calls +
		p.hash.latency.Calls + p.usn.changeCalls + p.usn.reasonCalls + p.ace.calls
	s.trackedCOPY += p.ntfs.FileCopyLatency.Total + p.ntfs.MetadataCopyLatency.Total
	if p.copyMetrics != nil {
		s.copyTop = p.copyMetrics.top3()
	}
	p.snapshot.Store(s)
}

func (p *ingestProgress) completeBatch(records int64) {
	if p == nil {
		return
	}
	p.batchesCompleted++
	p.recordsCompleted += records
	p.publish(0)
}

// emit reads only a published snapshot. While a long PostgreSQL call is in
// progress, the last checkpoint stays fixed and snapshot_age grows; the
// transaction clock continues. No uncommitted record is called "committed".
func (p *ingestProgress) emit(status string, now time.Time) {
	if p == nil {
		return
	}
	s := p.snapshot.Load()
	if s == nil {
		return
	}
	age := now.Sub(p.transactionStarted)
	if age < 0 {
		age = 0
	}
	snapshotAge := now.Sub(s.capturedAt)
	if snapshotAge < 0 {
		snapshotAge = 0
	}
	rate := 0.0
	if age > 0 {
		rate = float64(s.recordsRead) / age.Seconds()
	}
	fmt.Fprintf(p.out,
		"INGEST PROGRESS source=%s generation=%s status=%s batches_completed=%d/%d records_read=%d/%d committed=0 tx_age=%s snapshot_age=%s rate=%.1f_records_per_s read=%s batch_hash=%s prepare=%s source_sql=%s projection=%s ntfs_identity=%s tracked_copy=%s tracked_copy_calls=%d copy_top=%s\n",
		p.sourceID, p.generationID, status, s.batchesCompleted, p.batchesTotal,
		s.recordsRead, p.recordsTotal, age.Round(time.Millisecond),
		snapshotAge.Round(time.Millisecond), rate,
		s.read.Round(time.Millisecond), s.batchHash.Round(time.Millisecond),
		s.prepare.Round(time.Millisecond), s.sourceSQL.Round(time.Millisecond),
		s.projection.Round(time.Millisecond), s.identity.Round(time.Millisecond),
		s.trackedCOPY.Round(time.Millisecond), s.trackedCOPYCalls, s.copyTop,
	)
}

func (p *ingestProgress) start() {
	p.stopCh = make(chan struct{})
	p.finishedCh = make(chan struct{})
	go func() {
		ticker := time.NewTicker(p.interval)
		defer ticker.Stop()
		defer close(p.finishedCh)
		for {
			select {
			case <-p.stopCh:
				return
			case now := <-ticker.C:
				p.emit("inflight", now)
			}
		}
	}()
}

// stop waits for the heartbeat to finish; no background goroutine survives
// an accepted, rejected, canceled, or failed generation.
func (p *ingestProgress) stop() {
	p.stopOnce.Do(func() {
		close(p.stopCh)
		<-p.finishedCh
	})
}
