// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"time"

	"github.com/jackc/pgx/v5"
)

// Only the isolated continuous-private recovery runner opts into this path.
// Production generation ingestion and the independent replay verifier are unchanged.
type joinedBacklogSourceKey struct{}

// Joined-source and typed processing chunks may span signed source-batch
// boundaries. Every source row preserves its original batch identity and
// ordinal; individual P3/F3 table COPY memory ceilings stay independent.
// The processing-chunk setting closes cross-batch typed buffers, not the
// outer durable transaction.
const backlogDefaultJoinedSourceChunkRecords = 8192

type joinedBacklogChunkContextKey struct{}

func WithBacklogJoinedSourceChunkRecords(ctx context.Context, records int) (context.Context, error) {
    if ctx == nil {
        return nil, errors.New("FI joined source: context required")
    }
    switch records {
    case 32768, 65536, 98304, 131072:
        return context.WithValue(ctx, joinedBacklogChunkContextKey{}, records), nil
    default:
        return nil, errors.New("FI joined source: chunk records must be 32768, 65536, 98304, or 131072")
    }
}

func joinedBacklogChunkRecords(ctx context.Context) int {
    if ctx != nil {
        if n, ok := ctx.Value(joinedBacklogChunkContextKey{}).(int); ok {
            switch n {
            case 32768, 65536, 98304, 131072:
                return n
            }
        }
    }
    return backlogDefaultJoinedSourceChunkRecords
}

// Keep one compact, typed row in memory until the next signed-batch
// boundary. The former [][]any boxed eleven columns for every source row,
// holding those interface arrays live across an entire 32K-128K COPY chunk.
// pgx.CopyFromSlice creates the transient []any only when streaming to COPY.
type joinedBacklogSourceRow struct {
	batchIndex       int
	ordinal          int64
	version          string
	recordKind       string
	scopeID          string
	writtenAtUTC     time.Time
	writtenAtOriginal string
	recordBytes      int
	digest           [32]byte
}

type joinedBacklogSource struct {
	tx         pgx.Tx
	receipt    []byte
	descriptor BacklogCheckpointDescriptor
	index      int
	batchIndex int
	rows       []joinedBacklogSourceRow
	chunkRows  int
	copyCalls  uint64
	copyTime   time.Duration
	verifyTime time.Duration
	digest     hash.Hash
	records    uint64
	bytes      uint64
	families   map[string]uint64
}

func joinedBacklogActive(ctx context.Context) bool {
	return ctx != nil && ctx.Value(joinedBacklogSourceKey{}) != nil
}
func joinedBacklogSourceFromContext(ctx context.Context) *joinedBacklogSource {
	if ctx == nil {
		return nil
	}
	j, _ := ctx.Value(joinedBacklogSourceKey{}).(*joinedBacklogSource)
	return j
}

// A source marker and typed marker must be committed by the same transaction.
// A verified artifact marker, recorded immediately before this transaction,
// is mandatory. Every staged source envelope is then derived from the exact
// PreparedSourceRecord fed to the typed writer; no second JSONL parse occurs.
func beginJoinedBacklogSource(ctx context.Context, tx pgx.Tx, d BacklogCheckpointDescriptor, index int,
	receipt []byte, families map[string]uint64) (*joinedBacklogSource, error) {
	if tx == nil || ctx == nil || index < 1 || len(receipt) != 32 || families == nil {
		return nil, errors.New("FI joined source: invalid transaction or recovery context")
	}
	desc, err := hex.DecodeString(d.DigestSHA256)
	if err != nil {
		return nil, err
	}
	prev, err := hex.DecodeString(d.PreviousDigestSHA256)
	if err != nil {
		return nil, err
	}
	var deferred := deferredWindowFromContext(ctx)
	if deferred != nil {
		// This is the sole isolated-private exception to the usual prior
		// committed artifact marker. The same transaction will INSERT that
		// marker only AFTER verifying every signed data batch and SQL row.
		if err := deferred.check(ctx, d, index, deferred.root); err != nil {
			return nil, fmt.Errorf("FI joined source: deferred staged artifact invalid: %w", err)
		}
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM fi_recovery.verified_artifact_window
WHERE receipt_sha256=$1 AND window_index=$2)`, receipt, index).Scan(&exists); err != nil {
			return nil, err
		}
		if exists {
			return nil, errors.New("FI joined source: deferred artifact marker must not preexist")
		}
	} else {
		var artifact []byte
		err = tx.QueryRow(ctx, `SELECT descriptor_sha256 FROM fi_recovery.verified_artifact_window
WHERE receipt_sha256=$1 AND window_index=$2 AND source_id=$3 AND generation_id=$4`,
			receipt, index, d.SourceID, d.GenerationID).Scan(&artifact)
		if err != nil {
			return nil, fmt.Errorf("FI joined source: verified artifact marker missing: %w", err)
		}
		if subtle.ConstantTimeCompare(artifact, desc) != 1 {
			return nil, errors.New("FI joined source: verified artifact descriptor mismatch")
		}
	}
	var existing bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM fi_recovery.source_window
WHERE receipt_sha256=$1 AND window_index=$2)`, receipt, index).Scan(&existing); err != nil {
		return nil, err
	}
	if existing {
		return nil, errors.New("FI joined source: window already has a source marker")
	}
	var priorDescriptor []byte
	var priorEndBatch int
	var priorEndRecord int64
	err = tx.QueryRow(ctx, `SELECT descriptor_sha256,end_batch,end_record FROM fi_recovery.source_window
WHERE receipt_sha256=$1 AND window_index=$2`, receipt, index-1).Scan(&priorDescriptor, &priorEndBatch, &priorEndRecord)
	if err != nil {
		return nil, fmt.Errorf("FI joined source: previous source marker missing: %w", err)
	}
	if subtle.ConstantTimeCompare(priorDescriptor, prev) != 1 || priorEndBatch != d.StartBatch || priorEndRecord != int64(d.StartRecord) {
		return nil, errors.New("FI joined source: previous source marker is discontinuous")
	}
	chunkRows := joinedBacklogChunkRecords(ctx)
	return &joinedBacklogSource{tx: tx, receipt: receipt, descriptor: d, index: index,
		chunkRows: chunkRows, rows: make([]joinedBacklogSourceRow, 0, backlogDefaultJoinedSourceChunkRecords),
		digest: sha256.New(), families: families}, nil
}

// Flush only BETWEEN original signed source batches: no signed batch is
// split across joined-ledger COPY calls. Outer SQL commit remains atomic.
func shouldFlushJoinedSourceChunk(bufferedRows, incomingBatchRecords, maxRows int) bool {
	return bufferedRows > 0 && incomingBatchRecords > maxRows-bufferedRows
}

func (s *joinedBacklogSource) beginBatch(ctx context.Context, sourceBatchRecords int) error {
	if s == nil || sourceBatchRecords <= 0 || s.chunkRows <= 0 ||
		sourceBatchRecords > s.chunkRows {
		return errors.New("FI joined source: signed batch exceeds bounded COPY chunk")
	}
	if shouldFlushJoinedSourceChunk(len(s.rows), sourceBatchRecords, s.chunkRows) {
		return s.flush(ctx)
	}
	return nil
}

// add is retained for existing direct-call unit tests and fails closed on
// invalid source digests. The actual ingester supplies its already decoded
// digest to addPrepared, avoiding a second hex decode for every real row.
func (s *joinedBacklogSource) add(ctx context.Context, ordinal int64, p SourceRecord) error {
	digest, err := hex.DecodeString(p.RecordSHA256)
	if err != nil {
		return errors.New("FI joined source: invalid record digest")
	}
	return s.addPrepared(ctx, ordinal, p, digest)
}

func (s *joinedBacklogSource) addPrepared(ctx context.Context, ordinal int64, p SourceRecord, digest []byte) error {
	if s == nil || ordinal <= 0 || p.RecordBytes <= 0 || p.Record.RecordKind == "" {
		return errors.New("FI joined source: invalid source envelope")
	}
	if s.batchIndex < s.descriptor.StartBatch || s.batchIndex >= s.descriptor.EndBatch {
		return errors.New("FI joined source: batch index out of window")
	}
	if !backlogTypedKindAllowed(p.Record.RecordKind) {
		return fmt.Errorf("FI joined source: unsupported typed family %q", p.Record.RecordKind)
	}
	if len(digest) != 32 {
		return errors.New("FI joined source: invalid record digest")
	}
	// The caller has already decoded and validated the signed source
	// record digest. Store a fixed-size value, never a second live []byte.
	var sourceDigest [32]byte
	copy(sourceDigest[:], digest)
	backlogHashSourceRow(s.digest, s.batchIndex, ordinal, p.Record.Version, p.Record.RecordKind,
		p.Record.ScopeID, p.Record.WrittenAt, p.RecordBytes, sourceDigest[:])
	s.rows = append(s.rows, joinedBacklogSourceRow{
		batchIndex: s.batchIndex, ordinal: ordinal, version: p.Record.Version,
		recordKind: p.Record.RecordKind, scopeID: p.Record.ScopeID,
		writtenAtUTC: p.WrittenAtUTC, writtenAtOriginal: p.Record.WrittenAt,
		recordBytes: p.RecordBytes, digest: sourceDigest,
	})
	s.records++
	s.bytes += uint64(p.RecordBytes)
	s.families[p.Record.RecordKind]++
	if len(s.rows) > s.chunkRows {
		return errors.New("FI joined source: source batch outgrew chunk buffer")
	}
	return nil
}

func (s *joinedBacklogSource) flush(ctx context.Context) error {
	if len(s.rows) == 0 {
		return nil
	}
	cols := []string{"receipt_sha256", "window_index", "batch_index", "record_ordinal",
		"version", "record_kind", "scope_id", "written_at", "written_at_original", "record_bytes", "record_sha256"}
	started := time.Now()
	got, err := s.tx.CopyFrom(ctx, pgx.Identifier{"fi_recovery", "pending_source_record"}, cols,
		pgx.CopyFromSlice(len(s.rows), func(i int) ([]any, error) {
			r := &s.rows[i]
			return []any{s.receipt, s.index, r.batchIndex, r.ordinal,
				r.version, r.recordKind, r.scopeID, r.writtenAtUTC,
				r.writtenAtOriginal, r.recordBytes, r.digest[:]}, nil
		}))
	s.copyTime += time.Since(started)
	if err != nil {
		return fmt.Errorf("FI joined source: source COPY: %w", err)
	}
	if got != int64(len(s.rows)) {
		return fmt.Errorf("FI joined source: COPY mismatch %d of %d", got, len(s.rows))
	}
	s.rows = s.rows[:0]
	s.copyCalls++
	return nil
}

// finish verifies the SQL source identities against exactly the same hash
// accumulated while the normal typed ingester decoded source JSONL. The marker
// is inserted in the caller's typed-write transaction; a late failure rolls
// back BOTH source and typed windows, preserving the durable prefix.
func (s *joinedBacklogSource) finish(ctx context.Context) error {
	if err := s.flush(ctx); err != nil {
		return err
	}
	d := s.descriptor
	if s.records != d.EndRecord-d.StartRecord || s.bytes != d.DataBytes {
		return fmt.Errorf("FI joined source: source totals records=%d/%d bytes=%d/%d",
			s.records, d.EndRecord-d.StartRecord, s.bytes, d.DataBytes)
	}
	verifyStarted := time.Now()
	sqlHash, dbRecords, dbBytes, err := hashBacklogDatabaseSourceRows(ctx, s.tx, s.receipt, s.index)
	s.verifyTime += time.Since(verifyStarted)
	if err != nil {
		return fmt.Errorf("FI joined source: SQL verification: %w", err)
	}
	expected := s.digest.Sum(nil)
	if dbRecords != s.records || dbBytes != s.bytes || subtle.ConstantTimeCompare(sqlHash, expected) != 1 {
		return errors.New("FI joined source: persisted SQL rows differ from validated typed stream")
	}
	desc, err := hex.DecodeString(d.DigestSHA256)
	if err != nil {
		return err
	}
	prev, err := hex.DecodeString(d.PreviousDigestSHA256)
	if err != nil {
		return err
	}
	_, err = s.tx.Exec(ctx, `INSERT INTO fi_recovery.source_window (
receipt_sha256,window_index,descriptor_sha256,previous_digest_sha256,
start_batch,end_batch,start_record,end_record,staged_records,staged_bytes,rows_digest_sha256)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		s.receipt, s.index, desc, prev, d.StartBatch, d.EndBatch, int64(d.StartRecord), int64(d.EndRecord),
		int64(s.records), int64(s.bytes), expected)
	if err != nil {
		return fmt.Errorf("FI joined source: marker insert: %w", err)
	}
	return nil
}

// New mode bypasses StageVerifiedBacklogSourceWindow ONLY in the continuous
// private fixture. All completed-window and final-generation proofs remain.
func StageBacklogSourceAndTypedWindow(ctx context.Context, reader, writer *pgx.Conn,
	generation *PreparedGeneration, limits BacklogWindowLimits, index int, root string) error {
	if ctx == nil {
		return errors.New("FI joined source: nil context")
	}
	if reader == nil || writer == nil || generation == nil {
		return errors.New("FI joined source: distinct SQL connections and generation required")
	}
	// An interrupted pre-joined run can leave the source checkpoint committed
	// while its typed window is incomplete. Preserve that already-verified
	// source transaction and finish typed-only exactly once. Otherwise the new
	// joined path would reject an existing source marker on resume.
	descriptors, err := DescribeBacklogWindows(generation, limits)
	if err != nil {
		return err
	}
	if index < 0 || index >= len(descriptors) {
		return errors.New("FI joined source: window index out of bounds")
	}
	d := descriptors[index]
	receipt, err := hex.DecodeString(d.ReceiptSHA256)
	if err != nil {
		return err
	}
	digest, err := hex.DecodeString(d.DigestSHA256)
	if err != nil {
		return err
	}
	var committedSourceDigest []byte
	err = writer.QueryRow(ctx, `SELECT descriptor_sha256 FROM fi_recovery.source_window
WHERE receipt_sha256=$1 AND window_index=$2`, receipt, index).Scan(&committedSourceDigest)
	if err == nil {
		if subtle.ConstantTimeCompare(committedSourceDigest, digest) != 1 {
			return errors.New("FI joined source: pre-committed source descriptor conflicts with signed window")
		}
		// This call still checks full marker identity and family totals in the
		// existing SummarizeCommittedBacklogSourceWindow before projection.
		fmt.Printf("FI JOINED SOURCE RESUME window=%d source_marker=existing typed_mode=legacy\n", index)
		return StageBacklogTypedWindow(ctx, reader, writer, generation, limits, index, root)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("FI joined source: lookup existing source marker: %w", err)
	}
	// Non-nil sentinel. Typed stage constructs the transaction-bound writer.
	ctx = context.WithValue(ctx, joinedBacklogSourceKey{}, &joinedBacklogSource{})
	return StageBacklogTypedWindow(ctx, reader, writer, generation, limits, index, root)
}
