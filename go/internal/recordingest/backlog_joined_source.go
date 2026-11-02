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

	"github.com/jackc/pgx/v5"
)

// Only the isolated continuous-private recovery runner opts into this path.
// Production generation ingestion and the independent replay verifier are unchanged.
type joinedBacklogSourceKey struct{}

// Joined-source COPY chunks may span original signed source-batch boundaries,
// but every row retains its original batch index and ordinal. This changes
// ONLY the private, transaction-bound source-ledger COPY; P3/F3 typed COPY
// limits are independent and unchanged.
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

type joinedBacklogSource struct {
	tx         pgx.Tx
	receipt    []byte
	descriptor BacklogCheckpointDescriptor
	index      int
	batchIndex int
	rows       [][]any
	chunkRows  int
	copyCalls  uint64
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
		chunkRows: chunkRows, rows: make([][]any, 0, backlogDefaultJoinedSourceChunkRecords),
		digest: sha256.New(), families: families}, nil
}

func shouldFlushJoinedSourceChunk(bufferedRows, maxRows int) bool {
	return maxRows > 0 && bufferedRows >= maxRows
}

func (s *joinedBacklogSource) add(ctx context.Context, ordinal int64, p SourceRecord) error {
	if s == nil || ordinal <= 0 || p.RecordBytes <= 0 || p.Record.RecordKind == "" {
		return errors.New("FI joined source: invalid source envelope")
	}
	if s.batchIndex < s.descriptor.StartBatch || s.batchIndex >= s.descriptor.EndBatch {
		return errors.New("FI joined source: batch index out of window")
	}
	if !backlogTypedKindAllowed(p.Record.RecordKind) {
		return fmt.Errorf("FI joined source: unsupported typed family %q", p.Record.RecordKind)
	}
	digest, err := hex.DecodeString(p.RecordSHA256)
	if err != nil || len(digest) != 32 {
		return errors.New("FI joined source: invalid record digest")
	}
	backlogHashSourceRow(s.digest, s.batchIndex, ordinal, p.Record.Version, p.Record.RecordKind,
		p.Record.ScopeID, p.Record.WrittenAt, p.RecordBytes, digest)
	s.rows = append(s.rows, []any{s.receipt, s.index, s.batchIndex, ordinal, p.Record.Version,
		p.Record.RecordKind, p.Record.ScopeID, p.WrittenAtUTC, p.Record.WrittenAt, p.RecordBytes, digest})
	s.records++
	s.bytes += uint64(p.RecordBytes)
	s.families[p.Record.RecordKind]++
	if shouldFlushJoinedSourceChunk(len(s.rows), s.chunkRows) {
		return s.flush(ctx)
	}
	return nil
}

func (s *joinedBacklogSource) flush(ctx context.Context) error {
	if len(s.rows) == 0 {
		return nil
	}
	cols := []string{"receipt_sha256", "window_index", "batch_index", "record_ordinal",
		"version", "record_kind", "scope_id", "written_at", "written_at_original", "record_bytes", "record_sha256"}
	got, err := s.tx.CopyFrom(ctx, pgx.Identifier{"fi_recovery", "pending_source_record"}, cols, pgx.CopyFromRows(s.rows))
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
	sqlHash, dbRecords, dbBytes, err := hashBacklogDatabaseSourceRows(ctx, s.tx, s.receipt, s.index)
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
