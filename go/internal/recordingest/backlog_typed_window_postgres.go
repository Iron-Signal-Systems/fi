// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, in the repository root LICENSE file.

package recordingest

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// StageBacklogTypedWindow is an opt-in isolated-fixture prototype. It commits
// one bounded window's actual typed projections to the PRIVATE relational
// shadow, together with its completed-window marker, in one transaction.
//
// M6.1 source-bound captures may cross private typed windows. Restarts
// reconstruct missing capture context from durable private relational rows.
// Only a complete final window may close the generation. This path never
// marks any generation Accepted or modifies the canonical fi.* system of record.
func StageBacklogTypedWindow(
	ctx context.Context,
	reader, writer *pgx.Conn,
	generation *PreparedGeneration,
	limits BacklogWindowLimits,
	index int,
	privateRoot string,
) error {
	if ctx == nil || reader == nil || writer == nil || reader == writer {
		return errors.New("FI typed window: distinct reader and writer connections required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	windowStarted := time.Now()
	descriptors, err := DescribeBacklogWindows(generation, limits)
	if err != nil {
		return err
	}
	if index < 0 || index >= len(descriptors) {
		return errors.New("FI typed window: invalid index")
	}
	d := descriptors[index]
	if d.EndRecord > math.MaxInt64 || d.DataBytes > math.MaxInt64 {
		return errors.New("FI typed window: SQL count limits exceeded")
	}

	// Replay checks the full committed private source identity and immutable
	// bytes before opening the typed-write transaction. Unsupported families
	// fail closed, rather than accidentally dropping their child projections.
	familyCounts := make(map[string]uint64, 16)
	joined := joinedBacklogActive(ctx)
	var summary BacklogReplaySummary
	if joined {
		summary = BacklogReplaySummary{RecordCount: d.EndRecord - d.StartRecord, DataBytes: d.DataBytes,
			BatchCount: d.EndBatch - d.StartBatch, ReceiptSHA256: d.ReceiptSHA256, WindowDigestSHA256: d.DigestSHA256}
	} else {
		summary, err = SummarizeCommittedBacklogSourceWindow(ctx, reader, generation, limits, index,
			func(kind string, count uint64) error {
				if !backlogTypedKindAllowed(kind) {
					return fmt.Errorf("FI typed window: family %q requires cross-window projection acceptance", kind)
				}
				familyCounts[kind] += count
				return nil
			})
		if err != nil {
			return fmt.Errorf("FI typed window: source preflight: %w", err)
		}

	}
	if summary.RecordCount != d.EndRecord-d.StartRecord || summary.DataBytes != d.DataBytes {
		return errors.New("FI typed window: preflight receipt totals disagree")
	}

	var who, db string
	if err := writer.QueryRow(ctx, "SELECT current_user,current_database()").Scan(&who, &db); err != nil {
		return err
	}
	if who != "fi_ingest" || db != "fi" {
		return errors.New("FI typed window: unexpected database identity")
	}
	receipt, err := hex.DecodeString(d.ReceiptSHA256)
	if err != nil {
		return err
	}
	digest, err := hex.DecodeString(d.DigestSHA256)
	if err != nil {
		return err
	}
	tx, err := writer.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())
	lockKey := int64(binary.BigEndian.Uint64(receipt[:8]))
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1::bigint)", lockKey); err != nil {
		return err
	}
	var authoritative bool
	if err := tx.QueryRow(ctx, `
SELECT EXISTS (SELECT 1 FROM fi.recorded_generation
 WHERE source_id=$1 AND generation_id=$2)
`, d.SourceID, d.GenerationID).Scan(&authoritative); err != nil {
		return err
	}
	if authoritative {
		return errors.New("FI typed window: original generation already authoritative")
	}

	// Require committed exact source-window checkpoint, not merely the
	// existence of files or a prior attempted ingest.
	if !joined {
		var sourceDigest []byte
		if err := tx.QueryRow(ctx, `
SELECT descriptor_sha256 FROM fi_recovery.source_window
 WHERE receipt_sha256=$1 AND window_index=$2
`, receipt, index).Scan(&sourceDigest); err != nil {
			return err
		}
		if subtle.ConstantTimeCompare(sourceDigest, digest) != 1 {
			return errors.New("FI typed window: private source-window descriptor mismatch")
		}

	}
	copyMetrics := newIngestCopyMetrics()
	shadow := privateProjectionTx{Tx: &profiledIngestTx{Tx: tx, metrics: copyMetrics}}
	var joinedSource *joinedBacklogSource
	if joined {
		joinedSource, err = beginJoinedBacklogSource(ctx, tx, d, index, receipt, familyCounts)
		if err != nil {
			return fmt.Errorf("FI typed window: joined private source: %w", err)
		}
		ctx = context.WithValue(ctx, joinedBacklogSourceKey{}, joinedSource)
	}

	// Already completed is never inferred from shadow rows alone.
	var completedDigest []byte
	var shadowID, committedRecords, committedBytes int64
	var fromBatch, toBatch int
	var version string
	err = tx.QueryRow(ctx, `
SELECT descriptor_sha256,shadow_generation_id,start_batch,end_batch,
       committed_records,committed_bytes,ingest_version
FROM fi_recovery.typed_window
WHERE receipt_sha256=$1 AND window_index=$2
`, receipt, index).Scan(&completedDigest, &shadowID, &fromBatch, &toBatch,
		&committedRecords, &committedBytes, &version)
	if err == nil {
		if subtle.ConstantTimeCompare(completedDigest, digest) != 1 ||
			fromBatch != d.StartBatch || toBatch != d.EndBatch ||
			committedRecords != int64(summary.RecordCount) ||
			committedBytes != int64(summary.DataBytes) || version != IngestVersion {
			return errors.New("FI typed window: conflicting completed typed marker")
		}
		id, found, err := lookupRecordedGeneration(ctx, shadow, d.SourceID, d.GenerationID,
			generation.Receipt.TransferSHA256, generation.ReceiptSHA256)
		if err != nil {
			return err
		}
		if !found || id != shadowID {
			return errors.New("FI typed window: shadow generation identity changed")
		}
		if err := verifyBacklogShadowWindowCounts(ctx, shadow, id, generation.Batches[d.StartBatch:d.EndBatch],
			int64(summary.RecordCount), int64(summary.DataBytes)); err != nil {
			return err
		}
		if err := verifyBacklogWindowProjectionCoverage(ctx, shadow, id, generation.Batches[d.StartBatch:d.EndBatch]); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}

	if index > 0 {
		var priorDigest []byte
		if err := tx.QueryRow(ctx, `
SELECT descriptor_sha256 FROM fi_recovery.typed_window
WHERE receipt_sha256=$1 AND window_index=$2
`, receipt, index-1).Scan(&priorDigest); err != nil {
			return fmt.Errorf("FI typed window: preceding typed window missing: %w", err)
		}
		prev, err := hex.DecodeString(d.PreviousDigestSHA256)
		if err != nil {
			return err
		}
		if subtle.ConstantTimeCompare(priorDigest, prev) != 1 {
			return errors.New("FI typed window: preceding typed digest mismatch")
		}
	}

	id, found, err := lookupRecordedGeneration(ctx, shadow, d.SourceID, d.GenerationID,
		generation.Receipt.TransferSHA256, generation.ReceiptSHA256)
	if err != nil {
		return err
	}
	if index == 0 {
		if found {
			return errors.New("FI typed window: incomplete initial shadow generation without marker")
		}
		id, err = insertRecordedGeneration(ctx, shadow, generation)
		if err != nil {
			return err
		}
		var profile sourceBatchBulkProfile
		if _, err := copySourceBatches(ctx, shadow, id, generation.Batches, &profile); err != nil {
			return err
		}
	} else if !found {
		return errors.New("FI typed window: previous shadow generation missing")
	}

	batchIDs, err := lookupBacklogShadowBatchIDs(ctx, shadow, id, generation.Batches[d.StartBatch:d.EndBatch])
	if err != nil {
		return err
	}
	// The established file ingest path relies on window-scoped identity
	// caches, as well as deferred hash and ACE COPY writers. These are
	// reconstructed after each restart and MUST flush before committing.
	ctx = context.WithValue(ctx, ntfsObjectCacheContextKey{}, newNTFSObjectCache())
	ctx = context.WithValue(ctx, ntfsScopeIdentityCacheContextKey{}, newNTFSScopeIdentityCache())
	hashCopy := newContentHashCopyState()
	ctx = context.WithValue(ctx, contentHashCopyContextKey{}, hashCopy)
	aceCopy := newACECopyState()
	ctx = context.WithValue(ctx, aceCopyContextKey{}, aceCopy)
	ntfsTiming := &ntfsStageTimingCounters{}
	ctx = context.WithValue(ctx, ntfsStageTimingContextKey{}, ntfsTiming)
	usnCopy := newUSNChangeCopyState()
	ctx = context.WithValue(ctx, usnChangeCopyContextKey{}, usnCopy)
	captureState := newUSNCaptureState(d.SourceID, d.GenerationID)
	ctx = context.WithValue(ctx, usnCaptureContextKey{}, captureState)
	ctx = context.WithValue(ctx, backlogUSNCrossWindowContextKey{}, true)
	ctx = context.WithValue(ctx, usnTimingContextKey{}, &usnTimingCounters{})
	var profile ingestStageProfile
	profile.coverageBuffer = newSecurityCoverageBulkState(&profile)
	var totalRecords int64
	var totalBytes int64
	stageDir := filepath.Join(privateRoot, "receipt-"+d.ReceiptSHA256, fmt.Sprintf("window-%08d", index))
	setupElapsed := time.Since(windowStarted)
	batchStarted := time.Now()
	// Real typed processing chunks: COPY buffers may span original signed
	// batches; their final flush occurs at a configured chunk boundary.
	// All chunks still belong to this ONE transaction and marker.
	var typedChunk *backlogTypedChunkState
	chunkLimit := joinedBacklogChunkRecords(ctx)
	if joined && chunkLimit > backlogDefaultJoinedSourceChunkRecords {
		typedChunk = &backlogTypedChunkState{fileBulk: newFileObservationBulkState()}
	}
	chunkRows := 0
	chunkFirst := d.StartBatch
	chunkStarted := time.Now()
	var chunkSamples []backlogTypedChunkSample
	for offset := 0; offset < len(batchIDs); offset++ {
		globalIndex := d.StartBatch + offset
		batch := generation.Batches[globalIndex]
		batch.DataPath = filepath.Join(stageDir, fmt.Sprintf("batch-%08d.data", globalIndex))
		if joined {
			joinedSource.batchIndex = globalIndex
			if err := joinedSource.beginBatch(ctx, batch.Manifest.RecordCount); err != nil {
				return fmt.Errorf("FI typed window: joined COPY boundary before signed batch %d: %w", globalIndex, err)
			}
		}
		batchCtx := ctx
		finishChunk := false
		if typedChunk != nil {
			count := batch.Manifest.RecordCount
			if count <= 0 || count > chunkLimit-chunkRows {
				return fmt.Errorf("FI typed chunk: invalid signed batch size at %d", globalIndex)
			}
			chunkRows += count
			next := 0
			if offset+1 < len(batchIDs) {
				next = generation.Batches[globalIndex+1].Manifest.RecordCount
			}
			finishChunk, err = shouldFinishBacklogTypedChunk(chunkRows, next, chunkLimit)
			if err != nil {
				return err
			}
			batchCtx = context.WithValue(ctx, backlogTypedChunkContextKey{},
				backlogTypedChunkDirective{state: typedChunk, finish: finishChunk})
		}
		seen, err := ingestSourceBatch(batchCtx, shadow, d.SourceID, batchIDs[offset], batch, &profile)
		if err != nil {
			return fmt.Errorf("FI typed window: batch %d: %w", globalIndex, err)
		}
		totalRecords += seen
		totalBytes += batch.Manifest.DataBytes
		if finishChunk {
			if len(typedChunk.files) != 0 || len(typedChunk.security) != 0 ||
				len(typedChunk.fileBulk.records) != 0 || typedChunk.filesBytes() != 0 {
				return errors.New("FI typed chunk: buffers remained after required flush")
			}
			chunkSamples = append(chunkSamples, backlogTypedChunkSample{
				firstBatch: chunkFirst, endBatch: globalIndex + 1,
				records: chunkRows, duration: time.Since(chunkStarted),
			})
			chunkRows = 0
			chunkFirst = globalIndex + 1
			chunkStarted = time.Now()
		}
	}
	batchElapsed := time.Since(batchStarted)
	joinedStarted := time.Now()
	if joined {
		if err := joinedSource.finish(ctx); err != nil {
			return fmt.Errorf("FI typed window: joined source verification: %w", err)
		}
	}
	joinedElapsed := time.Since(joinedStarted)
	flushStarted := time.Now()
	if err := profile.coverageBuffer.flush(ctx, shadow); err != nil {
		return err
	}
	if err := usnCopy.flushAll(ctx, shadow); err != nil {
		return fmt.Errorf("FI typed window: final USN change/reason COPY: %w", err)
	}
	if err := hashCopy.flush(ctx, shadow); err != nil {
		return fmt.Errorf("FI typed window: final content hash COPY: %w", err)
	}
	if err := aceCopy.flushAll(ctx, shadow); err != nil {
		return fmt.Errorf("FI typed window: final ACE COPY: %w", err)
	}
	flushElapsed := time.Since(flushStarted)
	verifyStarted := time.Now()
	if totalRecords != int64(summary.RecordCount) || totalBytes != int64(summary.DataBytes) {
		return errors.New("FI typed window: processed counts differ from signed receipt")
	}
	countStarted := time.Now()
	if err := verifyBacklogShadowWindowCounts(ctx, shadow, id, generation.Batches[d.StartBatch:d.EndBatch],
		totalRecords, totalBytes); err != nil {
		return err
	}
	countElapsed := time.Since(countStarted)
	coverageStarted := time.Now()
	if err := verifyBacklogWindowProjectionCoverage(ctx, shadow, id, generation.Batches[d.StartBatch:d.EndBatch]); err != nil {
		return err
	}
	coverageElapsed := time.Since(coverageStarted)
	// Intermediate bounded windows may commit unfinished M6.1 captures.
	// The final window requires complete durable SQL counts for EVERY capture,
	// including captures that began in previously committed windows.
	if index == len(descriptors)-1 {
		if err := captureState.verify(); err != nil {
			return fmt.Errorf("FI typed window: M6.1 capture completeness: %w", err)
		}
		if err := verifyBacklogUSNCapturesComplete(ctx, shadow, id); err != nil {
			return fmt.Errorf("FI typed window: M6.1 capture completeness: %w", err)
		}
	}
	verifyElapsed := time.Since(verifyStarted)
	commitStarted := time.Now()
	_, err = tx.Exec(ctx, `
INSERT INTO fi_recovery.typed_window (
 receipt_sha256,window_index,descriptor_sha256,shadow_generation_id,
 start_batch,end_batch,committed_records,committed_bytes,ingest_version
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
`, receipt, index, digest, id, d.StartBatch, d.EndBatch, totalRecords, totalBytes, IngestVersion)
	if err != nil {
		return fmt.Errorf("FI typed window: atomic completion marker: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	commitElapsed := time.Since(commitStarted)
	windowElapsed := time.Since(windowStarted)
	keys := make([]string, 0, len(familyCounts))
	for k := range familyCounts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s:%d", k, familyCounts[k]))
	}
	fmt.Printf("FI REAL TYPED WINDOW index=%d records=%d families=%s ntfs_identity=%s ntfs_file_copy=%s ntfs_metadata_copy=%s security_events=%d security_fields=%d security_source_copy=%s security_event_copy=%s security_field_copy=%s\n", index, totalRecords, strings.Join(parts, ","), ntfsTiming.Identity, ntfsTiming.FileCopyLatency.String(), ntfsTiming.MetadataCopyLatency.String(), profile.SecurityBulk.Events, profile.SecurityBulk.Fields, profile.SecurityBulk.SourceLatency.String(), profile.SecurityBulk.EventLatency.String(), profile.SecurityBulk.FieldLatency.String())
	// Outer wall-clock stages partition the private typed window. The ingest
	// counters below are nested (some include COPY), so they are NOT additive.
	fmt.Printf("FI PRIVATE STAGE PROFILE index=%d records=%d joined=%t typed_total=%s setup=%s batch_ingest=%s joined_finish=%s deferred_flush=%s verification=%s verify_counts=%s verify_coverage=%s marker_commit=%s source_read=%s batch_hash=%s envelope_prepare=%s security_prepare=%s security_child_prepare=%s source_sql=%s file_projection_inclusive=%s security_id_lookup=%s security_source_copy=%s security_event_copy=%s security_scope_copy=%s security_field_copy=%s\n",
		index, totalRecords, joined, windowElapsed, setupElapsed, batchElapsed, joinedElapsed, flushElapsed, verifyElapsed, countElapsed, coverageElapsed, commitElapsed,
		profile.Read, profile.BatchHash, profile.Prepare, profile.SecurityBulk.Prepare, profile.SecurityBulk.ChildPrepare,
		profile.SourceSQL, profile.Projection, profile.SecurityBulk.IDLookup, profile.SecurityBulk.SourceCopy,
		profile.SecurityBulk.EventCopy, profile.SecurityBulk.ScopeCopy, profile.SecurityBulk.FieldCopy)
	if joinedSource != nil {
		fmt.Printf("FI JOINED SOURCE COPY CHUNKS COMMITTED window=%d chunk_limit=%d calls=%d records=%d copy_time=%s sql_verify_time=%s\n",
			index, joinedSource.chunkRows, joinedSource.copyCalls, joinedSource.records,
			joinedSource.copyTime.Round(time.Millisecond), joinedSource.verifyTime.Round(time.Millisecond))
	}
	for i, chunk := range chunkSamples {
		fmt.Printf("FI TYPED CHUNK COMMITTED window=%d chunk=%d limit=%d batches=%d..%d records=%d processing=%s\n",
			index, i, chunkLimit, chunk.firstBatch, chunk.endBatch, chunk.records, chunk.duration)
	}
	copyMetrics.report(os.Stdout, d.SourceID, d.GenerationID, fmt.Sprintf("PrivateWindow%dCommitted", index))
	return nil
}
func lookupBacklogShadowBatchIDs(ctx context.Context, tx pgx.Tx, id int64, batches []PreparedBatch) ([]int64, error) {
	ids := make([]string, len(batches))
	positions := make(map[string]int, len(batches))
	for i, b := range batches {
		if b.BatchID == "" {
			return nil, errors.New("FI typed window: empty batch ID")
		}
		if _, found := positions[b.BatchID]; found {
			return nil, errors.New("FI typed window: duplicated batch ID")
		}
		ids[i] = b.BatchID
		positions[b.BatchID] = i
	}
	rows, err := tx.Query(ctx, `
SELECT batch_id,source_batch_id FROM fi.source_batch
WHERE recorded_generation_id=$1 AND batch_id=ANY($2::text[])
`, id, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	found := make([]int64, len(ids))
	n := 0
	for rows.Next() {
		var key string
		var value int64
		if err := rows.Scan(&key, &value); err != nil {
			return nil, err
		}
		i, known := positions[key]
		if !known || value <= 0 || found[i] != 0 {
			return nil, errors.New("FI typed window: source-batch identity collision")
		}
		found[i] = value
		n++
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if n != len(ids) {
		return nil, errors.New("FI typed window: incomplete source-batch ID map")
	}
	return found, nil
}
func verifyBacklogShadowWindowCounts(ctx context.Context, tx pgx.Tx, id int64, batches []PreparedBatch, records, bytes int64) error {
	ids := make([]string, len(batches))
	for i, b := range batches {
		ids[i] = b.BatchID
	}
	var gotRecords, gotBytes int64
	err := tx.QueryRow(ctx, `
SELECT count(*),coalesce(sum(sr.record_bytes),0)::bigint
FROM fi.source_record sr
JOIN fi.source_batch sb ON sb.source_batch_id=sr.source_batch_id
WHERE sb.recorded_generation_id=$1 AND sb.batch_id=ANY($2::text[])
`, id, ids).Scan(&gotRecords, &gotBytes)
	if err != nil {
		return err
	}
	if gotRecords != records || gotBytes != bytes {
		return fmt.Errorf("FI typed window: projected source counts %d/%d differ from receipt %d/%d",
			gotRecords, gotBytes, records, bytes)
	}
	return nil
}

func backlogTypedKindAllowed(kind string) bool {
	switch kind {
	case "NTFSCollectionError", "SupportingSourceCollectionError", "WindowsSecurityEvent", "WindowsSecurityCoverage", "FileObservation", "USNReadBoundary", "USNObjectObservation", "USNContinuityGap", "CollectorIdentity", "DirectoryPrincipalSnapshot", "LocalPrincipalSnapshot", "SMBShareSnapshot", "WindowsSecurityContinuityGap":
		return true
	default:
		return false
	}
}
