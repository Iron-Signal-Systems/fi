// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
	"github.com/jackc/pgx/v5"
)

var (
	ErrGenerationConflict   = errors.New("FI relational generation identity conflict")
	ErrSourceRecordRejected = errors.New("FI relational source record rejected")
)

type IngestResult struct {
	AttemptID            string
	SourceID             string
	GenerationID         string
	TransferSHA256       string
	ReceiptSHA256        string
	Batches              int
	DataBytes            uint64
	RecordsSeen          int64
	RecordsCommitted     int64
	RecordedGenerationID int64
	Outcome              string
	SecurityMetrics      *CommittedSecurityIngestMetrics
}

type ingestStageProfile struct {
	Read           time.Duration
	BatchHash      time.Duration
	Prepare        time.Duration
	SourceSQL      time.Duration
	Projection     time.Duration
	BatchBulk      sourceBatchBulkProfile
	CoverageBulk   securityCoverageBulkProfile
	SecurityBulk   securityBulkTimingCounters
	coverageBuffer *securityCoverageBulkState
}

func IngestPreparedGeneration(ctx context.Context, connection *pgx.Conn, attemptID string, generation *PreparedGeneration) (IngestResult, error) {
	if ctx == nil || connection == nil || generation == nil || attemptID == "" {
		return IngestResult{}, errors.New("FI relational generation ingest input is incomplete")
	}
	started := time.Now()
	selectedSecurityBulk := securityBulkLimitsFromContext(ctx)
	var profile ingestStageProfile
	profile.coverageBuffer = newSecurityCoverageBulkState(&profile)
	usnTiming := &usnTimingCounters{}
	ctx = context.WithValue(ctx, usnTimingContextKey{}, usnTiming)
	ntfsStages := &ntfsStageTimingCounters{}
	ctx = context.WithValue(ctx, ntfsStageTimingContextKey{}, ntfsStages)
	descriptor := generation.Receipt.Descriptor
	ctx = context.WithValue(ctx, usnCaptureContextKey{}, newUSNCaptureState(descriptor.SourceID, descriptor.GenerationID))
	result := IngestResult{
		AttemptID: attemptID, SourceID: descriptor.SourceID, GenerationID: descriptor.GenerationID,
		TransferSHA256: generation.Receipt.TransferSHA256, ReceiptSHA256: generation.ReceiptSHA256,
		Batches: len(generation.Batches), DataBytes: generation.Receipt.DataBytes,
	}

	tx, err := connection.Begin(ctx)
	if err != nil {
		return result, fmt.Errorf("begin FI relational generation transaction: %w", err)
	}
	// Record every pgx.CopyFrom call by relation without changing the
	// authoritative transaction or any relational insert ordering.
	copyMetrics := newIngestCopyMetrics()
	tx = &profiledIngestTx{Tx: tx, metrics: copyMetrics}
	identityCache := newNTFSObjectCache()
	ctx = context.WithValue(ctx, ntfsObjectCacheContextKey{}, identityCache)
	scopeCache := newNTFSScopeIdentityCache()
	ctx = context.WithValue(ctx, ntfsScopeIdentityCacheContextKey{}, scopeCache)
	aceCopy := newACECopyState()
	ctx = context.WithValue(ctx, aceCopyContextKey{}, aceCopy)
	usnCopy := newUSNChangeCopyState()
	ctx = context.WithValue(ctx, usnChangeCopyContextKey{}, usnCopy)
	hashCopy := newContentHashCopyState()
	ctx = context.WithValue(ctx, contentHashCopyContextKey{}, hashCopy)
	// A read-only heartbeat reports immutable snapshots during this transaction.
	progress := newIngestProgress(os.Stdout, result.SourceID, result.GenerationID,
		len(generation.Batches), int64(generation.Receipt.RecordCount), time.Now(),
		&profile, ntfsStages, hashCopy, usnCopy, aceCopy)
	ctx = context.WithValue(ctx, ingestProgressContextKey{}, progress)
	progress.copyMetrics = copyMetrics
	progress.start()
	committed := false
	defer func() {
		outcome := "not_confirmed"
		if committed {
			outcome = "accepted"
		}
		copyMetrics.report(os.Stdout, result.SourceID, result.GenerationID, outcome)
	}()
	defer func() {
		if !committed {
			_ = tx.Rollback(context.Background())
		}
	}()
	defer func() {
		progress.stop()
		if !committed {
			progress.emit("uncommitted", time.Now())
		}
	}()

	existingID, found, err := lookupRecordedGeneration(ctx, tx, descriptor.SourceID, descriptor.GenerationID, generation.Receipt.TransferSHA256, generation.ReceiptSHA256)
	if err != nil {
		return result, failIngestAttempt(ctx, connection, tx, result, "IdentityCheck", "DATABASE_IDENTITY_CHECK_FAILED", err)
	}
	if found {
		result.RecordedGenerationID = existingID
		result.RecordsSeen = int64(generation.Receipt.RecordCount)
		result.Outcome = "AlreadyAccepted"
		if err := tx.Rollback(ctx); err != nil {
			return result, fmt.Errorf("rollback FI already-accepted check: %w", err)
		}
		committed = true
		zero := int64(0)
		seen := result.RecordsSeen
		if err := WriteAttemptTerminal(ctx, connection, JournalEvent{
			AttemptID: attemptID, SourceID: result.SourceID, GenerationID: result.GenerationID, TransferSHA256: result.TransferSHA256,
			Outcome: "AlreadyAccepted", Stage: "IdentityCheck", RecordsSeen: &seen, RecordsCommitted: &zero,
		}); err != nil {
			return result, err
		}
		return result, nil
	}

	recordedGenerationID, err := insertRecordedGeneration(ctx, tx, generation)
	if err != nil {
		return result, failIngestAttempt(ctx, connection, tx, result, "AuthoritativeRecord", "GENERATION_INSERT_FAILED", err)
	}
	result.RecordedGenerationID = recordedGenerationID

	// Insert the complete immutable batch manifest set first. All database-
	// generated batch identities are mapped back to the original receipt order.
	// Source-record ingestion then proceeds in precisely that original order.
	sourceBatchIDs, err := copySourceBatches(ctx, tx, recordedGenerationID, generation.Batches, &profile.BatchBulk)
	progress.publish(0)
	if err != nil {
		return result, failIngestAttempt(ctx, connection, tx, result, "AuthoritativeRecord", "SOURCE_BATCH_INSERT_FAILED", err)
	}
	for i, batch := range generation.Batches {
		seen, err := ingestSourceBatch(ctx, tx, descriptor.SourceID, sourceBatchIDs[i], batch, &profile)
		result.RecordsSeen += seen
		if err != nil {
			return result, rejectIngestAttempt(ctx, connection, tx, result, err)
		}
		progress.completeBatch(seen)
	}
	// The last batch may end in coverage records. Make them relationally
	// complete before counting projections or committing the generation.
	if err := profile.coverageBuffer.flush(ctx, tx); err != nil {
		return result, rejectIngestAttempt(ctx, connection, tx, result, err)
	}

	if result.RecordsSeen != int64(generation.Receipt.RecordCount) {
		return result, rejectIngestAttempt(ctx, connection, tx, result, fmt.Errorf("generation source-record count %d does not match recorder receipt %d", result.RecordsSeen, generation.Receipt.RecordCount))
	}
	usnFlushStarted := time.Now()
	if err := usnCopy.flushAll(ctx, tx); err != nil {
		return result, rejectIngestAttempt(ctx, connection, tx, result, err)
	}
	usnFinalFlush := time.Since(usnFlushStarted)
	profile.Projection += usnFinalFlush

	hashFlushStarted := time.Now()
	if err := hashCopy.flush(ctx, tx); err != nil {
		return result, rejectIngestAttempt(ctx, connection, tx, result, err)
	}
	hashFinalFlush := time.Since(hashFlushStarted)
	profile.Projection += hashFinalFlush

	aceFlushStarted := time.Now()
	if err := aceCopy.flushAll(ctx, tx); err != nil {
		return result, rejectIngestAttempt(ctx, connection, tx, result, err)
	}
	aceFinalFlush := time.Since(aceFlushStarted)
	profile.Projection += aceFinalFlush

	if err := ctx.Value(usnCaptureContextKey{}).(*usnCaptureState).verify(); err != nil {
		return result, rejectIngestAttempt(ctx, connection, tx, result, err)
	}
	if err := verifyGenerationProjectionCoverage(ctx, tx, recordedGenerationID); err != nil {
		return result, rejectIngestAttempt(ctx, connection, tx, result, err)
	}

	result.RecordsCommitted = result.RecordsSeen
	result.Outcome = "Accepted"
	seen := result.RecordsSeen
	committedCount := result.RecordsCommitted
	transfer, err := decodeHex(result.TransferSHA256, 32, true, "accepted.transfer_sha256")
	if err != nil {
		return result, err
	}
	_, err = tx.Exec(ctx, `
INSERT INTO fi.ingest_journal (
 attempt_id,event_sequence,source_id,generation_id,transfer_sha256,outcome,stage,records_seen,records_committed,ingest_version
) VALUES ($1,2,$2,$3,$4,'Accepted','AuthoritativeRecord',$5,$6,$7)
`, attemptID, result.SourceID, result.GenerationID, transfer, seen, committedCount, IngestVersion)
	if err != nil {
		return result, fmt.Errorf("write FI accepted ingest journal event: %w", err)
	}

	commitStarted := time.Now()
	if err := tx.Commit(ctx); err != nil {
		return result, fmt.Errorf("commit FI relational generation: %w", err)
	}
	committed = true
	progress.stop() // No heartbeat after successful publication.
	commitElapsed := time.Since(commitStarted)
	// Only a confirmed COMMIT may publish a generation performance sample.
	// Failures and AlreadyAccepted outcomes must not train an adaptive policy.
	result.SecurityMetrics = committedSecurityIngestMetrics(result, &profile,
		selectedSecurityBulk, time.Since(started))
	fmt.Printf(
		"INGEST HASH COPY source=%s generation=%s rows=%d calls=%d copy=%s final_flush=%s\n",
		result.SourceID, result.GenerationID,
		hashCopy.copied, hashCopy.calls,
		hashCopy.duration.Round(time.Millisecond),
		hashFinalFlush.Round(time.Millisecond),
	)

	// One bounded telemetry record per committed generation. These timings
	// are individual pgx.CopyFrom call durations, not SQL-only or disk-only time.
	// Keep the existing aggregate log fields unchanged for baseline comparisons.
	fmt.Printf(
		"INGEST COPY LATENCY FILE source=%s generation=%s hash={%s} file={%s} metadata={%s}\n",
		result.SourceID, result.GenerationID,
		hashCopy.latency.String(),
		ntfsStages.FileCopyLatency.String(),
		ntfsStages.MetadataCopyLatency.String(),
	)
	fmt.Printf(
		"INGEST COPY LATENCY SECURITY source=%s generation=%s source_copy={%s} event={%s} scopes={%s} fields={%s}\n",
		result.SourceID, result.GenerationID,
		profile.SecurityBulk.SourceLatency.String(),
		profile.SecurityBulk.EventLatency.String(),
		profile.SecurityBulk.ScopeLatency.String(),
		profile.SecurityBulk.FieldLatency.String(),
	)

	fmt.Printf(
		"INGEST SOURCE BATCH COPY source=%s generation=%s rows=%d calls=%d prepare=%s copy=%s id_lookup=%s\n",
		result.SourceID, result.GenerationID,
		profile.BatchBulk.Rows, profile.BatchBulk.Copies,
		profile.BatchBulk.Prepare.Round(time.Millisecond),
		profile.BatchBulk.Copy.Round(time.Millisecond),
		profile.BatchBulk.Lookup.Round(time.Millisecond),
	)

	fmt.Printf(
		"INGEST SECURITY COVERAGE COPY source=%s generation=%s records=%d policies=%d roots=%d chunks=%d prepare=%s copy=%s\n",
		result.SourceID, result.GenerationID,
		profile.CoverageBulk.Records, profile.CoverageBulk.Policies,
		profile.CoverageBulk.Roots, profile.CoverageBulk.Chunks,
		profile.CoverageBulk.Prepare.Round(time.Millisecond),
		profile.CoverageBulk.Copy.Round(time.Millisecond),
	)

	fmt.Printf(
		"INGEST SECURITY BULK source=%s generation=%s batches=%d events=%d scopes=%d fields=%d prepare=%s source_copy=%s id_lookup=%s event_copy=%s child_prepare=%s scope_copy=%s field_copy=%s profile=%s max_events=%d max_bytes=%d\n",
		result.SourceID, result.GenerationID,
		profile.SecurityBulk.Batches,
		profile.SecurityBulk.Events,
		profile.SecurityBulk.Scopes,
		profile.SecurityBulk.Fields,
		profile.SecurityBulk.Prepare.Round(time.Millisecond),
		profile.SecurityBulk.SourceCopy.Round(time.Millisecond),
		profile.SecurityBulk.IDLookup.Round(time.Millisecond),
		profile.SecurityBulk.EventCopy.Round(time.Millisecond),
		profile.SecurityBulk.ChildPrepare.Round(time.Millisecond),
		profile.SecurityBulk.ScopeCopy.Round(time.Millisecond),
		profile.SecurityBulk.FieldCopy.Round(time.Millisecond),
		selectedSecurityBulk.Name, selectedSecurityBulk.MaxRecords, selectedSecurityBulk.MaxBytes,
	)
	fmt.Printf(
		"INGEST USN COPY source=%s generation=%s change_rows=%d reason_rows=%d change_calls=%d reason_calls=%d copy=%s final_flush=%s\n",
		result.SourceID, result.GenerationID,
		usnCopy.changeRows, usnCopy.reasonRows,
		usnCopy.changeCalls, usnCopy.reasonCalls,
		usnCopy.duration.Round(time.Millisecond),
		usnFinalFlush.Round(time.Millisecond),
	)
	fmt.Printf(
		"INGEST ACE COPY source=%s generation=%s dacl_rows=%d sacl_rows=%d calls=%d copy=%s final_flush=%s\n",
		result.SourceID, result.GenerationID,
		aceCopy.daclRows, aceCopy.saclRows, aceCopy.calls,
		aceCopy.duration.Round(time.Millisecond),
		aceFinalFlush.Round(time.Millisecond),
	)
	total := time.Since(started)
	measured := profile.Read + profile.BatchHash + profile.Prepare +
		profile.SourceSQL + profile.Projection + commitElapsed +
		profile.BatchBulk.Prepare + profile.BatchBulk.Copy + profile.BatchBulk.Lookup

	fmt.Printf(
		"INGEST PROFILE source=%s generation=%s records=%d total=%s read=%s batch_hash=%s prepare=%s source_sql=%s projection=%s commit=%s other=%s\n",
		result.SourceID, result.GenerationID, result.RecordsSeen,
		total.Round(time.Millisecond),
		profile.Read.Round(time.Millisecond),
		profile.BatchHash.Round(time.Millisecond),
		profile.Prepare.Round(time.Millisecond),
		profile.SourceSQL.Round(time.Millisecond),
		profile.Projection.Round(time.Millisecond),
		commitElapsed.Round(time.Millisecond),
		(total - measured).Round(time.Millisecond),
	)

	accounted := usnTiming.Boundary + usnTiming.Object +
		usnTiming.Observation + usnTiming.Changes + usnTiming.Nested

	fmt.Printf(
		"INGEST USN PROFILE source=%s generation=%s observations=%d total=%s boundary=%s object=%s observation_insert=%s changes=%s nested=%s other=%s\n",
		result.SourceID, result.GenerationID, usnTiming.Observations,
		usnTiming.Total.Round(time.Millisecond),
		usnTiming.Boundary.Round(time.Millisecond),
		usnTiming.Object.Round(time.Millisecond),
		usnTiming.Observation.Round(time.Millisecond),
		usnTiming.Changes.Round(time.Millisecond),
		usnTiming.Nested.Round(time.Millisecond),
		(usnTiming.Total - accounted).Round(time.Millisecond),
	)
	fmt.Printf(
		"INGEST NTFS CACHE source=%s generation=%s hits=%d misses=%d entries=%d evictions=%d\n",
		result.SourceID, result.GenerationID,
		identityCache.hits, identityCache.misses, len(identityCache.objects), identityCache.evictions,
	)
	fmt.Printf(
		"INGEST NTFS STAGES source=%s generation=%s observations=%d total=%s identity=%s file=%s metadata=%s hashes=%s prefix=%s reparse=%s streams=%s security=%s sacl=%s warnings=%s other=%s\n",
		result.SourceID, result.GenerationID,
		ntfsStages.Observations,
		ntfsStages.Total.Round(time.Millisecond),
		ntfsStages.Identity.Round(time.Millisecond),
		ntfsStages.File.Round(time.Millisecond),
		ntfsStages.Metadata.Round(time.Millisecond),
		ntfsStages.Hashes.Round(time.Millisecond),
		ntfsStages.Prefix.Round(time.Millisecond),
		ntfsStages.Reparse.Round(time.Millisecond),
		ntfsStages.Streams.Round(time.Millisecond),
		ntfsStages.Security.Round(time.Millisecond),
		ntfsStages.SACL.Round(time.Millisecond),
		ntfsStages.Warnings.Round(time.Millisecond),
		(ntfsStages.Total - ntfsStages.accounted()).Round(time.Millisecond),
	)

	fmt.Printf(
		"INGEST SCOPE CACHE source=%s generation=%s volume_hits=%d volume_misses=%d volume_entries=%d root_hits=%d root_misses=%d root_entries=%d\n",
		result.SourceID, result.GenerationID,
		scopeCache.volumeHits, scopeCache.volumeMisses, len(scopeCache.volumes),
		scopeCache.rootHits, scopeCache.rootMisses, len(scopeCache.roots),
	)

	return result, nil
}

func lookupRecordedGeneration(ctx context.Context, tx pgx.Tx, sourceID, generationID, transferSHA256, receiptSHA256 string) (int64, bool, error) {
	var id int64
	var storedTransfer []byte
	var storedReceipt []byte
	err := tx.QueryRow(ctx, `SELECT recorded_generation_id,transfer_sha256,receipt_sha256 FROM fi.recorded_generation WHERE source_id=$1 AND generation_id=$2`, sourceID, generationID).Scan(&id, &storedTransfer, &storedReceipt)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	wantTransfer, err := decodeHex(transferSHA256, 32, true, "generation.transfer_sha256")
	if err != nil {
		return 0, false, err
	}
	wantReceipt, err := decodeHex(receiptSHA256, 32, true, "generation.receipt_sha256")
	if err != nil {
		return 0, false, err
	}
	if !bytesEqual(storedTransfer, wantTransfer) || !bytesEqual(storedReceipt, wantReceipt) {
		return 0, false, ErrGenerationConflict
	}
	return id, true, nil
}

func insertRecordedGeneration(ctx context.Context, tx pgx.Tx, generation *PreparedGeneration) (int64, error) {
	receipt := generation.Receipt
	descriptor := receipt.Descriptor
	canonical, err := decodeHex(descriptor.CanonicalSHA256, 32, true, "generation.canonical_sha256")
	if err != nil {
		return 0, err
	}
	encoded, err := decodeHex(descriptor.EncodedDataSHA256, 32, true, "generation.encoded_data_sha256")
	if err != nil {
		return 0, err
	}
	metadata, err := decodeHex(receipt.MetadataSHA256, 32, true, "generation.metadata_sha256")
	if err != nil {
		return 0, err
	}
	transfer, err := decodeHex(receipt.TransferSHA256, 32, true, "generation.transfer_sha256")
	if err != nil {
		return 0, err
	}
	receiptSHA, err := decodeHex(generation.ReceiptSHA256, 32, true, "generation.receipt_sha256")
	if err != nil {
		return 0, err
	}
	var id int64
	err = tx.QueryRow(ctx, `
INSERT INTO fi.recorded_generation (
 receipt_version,descriptor_version,source_id,generation_id,canonical_version,data_encoding,artifact_count,source_bytes,
 canonical_bytes,canonical_sha256,encoded_data_bytes,encoded_data_sha256,metadata_bytes,metadata_sha256,transfer_bytes,transfer_sha256,
 batch_count,data_bytes,record_count,receipt_bytes,receipt_sha256,ingest_version
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)
RETURNING recorded_generation_id
`, receipt.Version, descriptor.Version, descriptor.SourceID, descriptor.GenerationID, descriptor.CanonicalVersion, descriptor.DataEncoding,
		int64(descriptor.ArtifactCount), int64(descriptor.SourceBytes), int64(descriptor.CanonicalBytes), canonical, int64(descriptor.EncodedDataBytes), encoded,
		int64(receipt.MetadataBytes), metadata, int64(receipt.TransferBytes), transfer, int64(receipt.BatchCount), int64(receipt.DataBytes),
		int64(receipt.RecordCount), generation.ReceiptBytes, receiptSHA, IngestVersion).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("insert FI recorded generation: %w", err)
	}
	return id, nil
}

func ingestSourceBatch(ctx context.Context, tx pgx.Tx, sourceID string, sourceBatchID int64, batch PreparedBatch, profile *ingestStageProfile) (int64, error) {
	if profile.coverageBuffer == nil {
		profile.coverageBuffer = newSecurityCoverageBulkState(profile)
	}
	file, err := os.Open(batch.DataPath)
	if err != nil {
		return 0, fmt.Errorf("open FI staged source batch: %w", err)
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	hasher := sha256.New()
	var ordinal int64
	progress, _ := ctx.Value(ingestProgressContextKey{}).(*ingestProgress)
	if progress != nil {
		// Publish the final partial-batch count even on rejection.
		defer func() { progress.publish(ordinal) }()
	}
	var byteCount int64
	var pendingSecurity []securityBulkRecord
	var pendingSecurityBytes int64
	securityLimits := securityBulkLimitsFromContext(ctx)
	// This run counter is local to ONE signed source batch, even when the
	// pending Security COPY buffer flushes several times within that batch.
	var contiguousSecurity int
	var pendingFiles []fileSourceBulkRecord
	var pendingFileBytes int64
	fileBulk := newFileObservationBulkState()
	ctx = context.WithValue(ctx, fileObservationBulkContextKey{}, fileBulk)
	flushFiles := func() error {
		if len(pendingFiles) == 0 {
			return nil
		}
		first := pendingFiles[0].ordinal
		last := pendingFiles[len(pendingFiles)-1].ordinal
		if err := copyFileSourceBulk(ctx, tx, sourceBatchID, pendingFiles, profile); err != nil {
			return fmt.Errorf("%w: batch %s FileObservation source records %d-%d: %v", ErrSourceRecordRejected, batch.BatchID, first, last, err)
		}
		projectStarted := time.Now()
		defer func() { profile.Projection += time.Since(projectStarted) }()
		for _, item := range pendingFiles {
			if item.prepared.Record.RecordKind == "USNObjectObservation" {
				projectCtx := context.WithValue(ctx, fileObservationBulkBytesContextKey{}, item.prepared.RecordBytes)
				if err := ProjectSourceRecord(projectCtx, tx, sourceID, item.sourceRecordID, item.prepared); err != nil {
					return fmt.Errorf("%w: batch %s record %d (USNObjectObservation): %v", ErrSourceRecordRejected, batch.BatchID, item.ordinal, err)
				}
				continue
			}
			var value fileObservationPayload
			if err := decodeStrictPayload(item.prepared.Record.Payload, &value); err != nil {
				return fmt.Errorf("%w: batch %s record %d (FileObservation): %v", ErrSourceRecordRejected, batch.BatchID, item.ordinal, projectionDecodeError("FileObservation", err))
			}
			value.NTFS.ContentHashes = &value.ContentHashes
			if err := ntfs.ValidateObservation(value.NTFS); err != nil {
				return fmt.Errorf("%w: batch %s record %d (FileObservation): %v", ErrSourceRecordRejected, batch.BatchID, item.ordinal, projectionValidationError("FileObservation", err))
			}
			if value.NTFS.GovernedRoot.ScopeID != item.prepared.Record.ScopeID {
				return fmt.Errorf("%w: batch %s record %d (FileObservation): governed-root scope does not match source envelope", ErrSourceRecordRejected, batch.BatchID, item.ordinal)
			}
			if err := fileBulk.add(ctx, tx, fileObservationBulkRecord{
				sourceID: sourceID, sourceRecordID: item.sourceRecordID, ordinal: item.ordinal,
				value: value.NTFS, hashes: &value.ContentHashes, bytes: int64(item.prepared.RecordBytes),
			}); err != nil {
				return fmt.Errorf("%w: batch %s record %d (FileObservation): %v", ErrSourceRecordRejected, batch.BatchID, item.ordinal, err)
			}
		}
		if err := fileBulk.flush(ctx, tx); err != nil {
			return fmt.Errorf("%w: batch %s FileObservation projection records %d-%d: %v", ErrSourceRecordRejected, batch.BatchID, first, last, err)
		}
		pendingFiles = nil
		pendingFileBytes = 0
		return nil
	}
	flushSecurity := func() error {
		if len(pendingSecurity) == 0 {
			return nil
		}
		first := pendingSecurity[0].ordinal
		last := pendingSecurity[len(pendingSecurity)-1].ordinal
		if err := copySecurityBulk(ctx, tx, sourceBatchID, pendingSecurity, profile); err != nil {
			return fmt.Errorf("%w: batch %s Security records %d-%d: %v", ErrSourceRecordRejected, batch.BatchID, first, last, err)
		}
		profile.SecurityBulk.SourceBytes += pendingSecurityBytes
		pendingSecurity = nil
		pendingSecurityBytes = 0
		return nil
	}
	for {
		readStarted := time.Now()
		raw, readErr := reader.ReadBytes('\n')
		profile.Read += time.Since(readStarted)
		if len(raw) == 0 && errors.Is(readErr, io.EOF) {
			break
		}
		if len(raw) == 0 && readErr != nil {
			return ordinal, fmt.Errorf("read FI source batch: %w", readErr)
		}
		if raw[len(raw)-1] != '\n' {
			return ordinal, fmt.Errorf("%w: batch %s record %d is missing final LF", ErrSourceRecordRejected, batch.BatchID, ordinal+1)
		}
		ordinal++
		// Only snapshot at bounded record checkpoints, never log per record.
		if progress != nil && ordinal%ingestProgressRecordCheckpoint == 0 {
			progress.publish(ordinal)
		}
		byteCount += int64(len(raw))
		hashStarted := time.Now()
		_, _ = hasher.Write(raw)
		profile.BatchHash += time.Since(hashStarted)

		prepareStarted := time.Now()
		prepared, err := PrepareSourceRecord(raw)
		profile.Prepare += time.Since(prepareStarted)
		if err != nil {
			return ordinal, fmt.Errorf("%w: batch %s record %d: %v", ErrSourceRecordRejected, batch.BatchID, ordinal, err)
		}
		digest, err := decodeHex(prepared.RecordSHA256, 32, true, "source_record.record_sha256")
		if err != nil {
			return ordinal, err
		}
		// Coverage records can span source batches. Flush before the next
		// distinct kind to preserve relational projection order.
		if prepared.Record.RecordKind != "WindowsSecurityCoverage" {
			if err := profile.coverageBuffer.flush(ctx, tx); err != nil {
				return ordinal, fmt.Errorf("%w: batch %s Security coverage COPY: %v", ErrSourceRecordRejected, batch.BatchID, err)
			}
		}
		if prepared.Record.RecordKind == "WindowsSecurityEvent" {
			contiguousSecurity++
			if contiguousSecurity > profile.SecurityBulk.MaxContiguousSecurity {
				profile.SecurityBulk.MaxContiguousSecurity = contiguousSecurity
			}
			if err := flushFiles(); err != nil {
				return ordinal, err
			}
			securityPrepareStarted := time.Now()
			securityRecord, err := prepareSecurityBulkRecord(ordinal, prepared, digest)
			profile.SecurityBulk.Prepare += time.Since(securityPrepareStarted)
			if err != nil {
				return ordinal, fmt.Errorf("%w: batch %s record %d (WindowsSecurityEvent): %v", ErrSourceRecordRejected, batch.BatchID, ordinal, err)
			}
			if securityLimits.shouldFlushBefore(
				len(pendingSecurity), pendingSecurityBytes, int64(prepared.RecordBytes),
			) {
				if err := flushSecurity(); err != nil {
					return ordinal, err
				}
			}
			pendingSecurity = append(pendingSecurity, securityRecord)
			pendingSecurityBytes += int64(prepared.RecordBytes)
			if readErr != nil {
				if errors.Is(readErr, io.EOF) {
					return ordinal, fmt.Errorf("%w: batch %s ended without final LF", ErrSourceRecordRejected, batch.BatchID)
				}
				return ordinal, fmt.Errorf("read FI source batch: %w", readErr)
			}
			continue
		}
		contiguousSecurity = 0
		if err := flushSecurity(); err != nil {
			return ordinal, err
		}
		if prepared.Record.RecordKind == "FileObservation" || prepared.Record.RecordKind == "USNObjectObservation" {
			if len(pendingFiles) >= fileSourceBulkMaxRecords ||
				(len(pendingFiles) > 0 && pendingFileBytes+int64(prepared.RecordBytes) > fileSourceBulkMaxBytes) {
				if err := flushFiles(); err != nil {
					return ordinal, err
				}
			}
			pendingFiles = append(pendingFiles, fileSourceBulkRecord{
				ordinal: ordinal, prepared: prepared, digest: digest,
			})
			pendingFileBytes += int64(prepared.RecordBytes)
			if readErr != nil {
				if errors.Is(readErr, io.EOF) {
					return ordinal, fmt.Errorf("%w: batch %s ended without final LF", ErrSourceRecordRejected, batch.BatchID)
				}
				return ordinal, fmt.Errorf("read FI source batch: %w", readErr)
			}
			continue
		}
		if err := flushFiles(); err != nil {
			return ordinal, err
		}
		var sourceRecordID int64
		sqlStarted := time.Now()
		err = tx.QueryRow(ctx, `
INSERT INTO fi.source_record (
 source_batch_id,record_ordinal,version,record_kind,scope_id,written_at,record_bytes,record_sha256,ingest_version
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
RETURNING source_record_id
`, sourceBatchID, ordinal, prepared.Record.Version, prepared.Record.RecordKind, prepared.Record.ScopeID, prepared.WrittenAtUTC,
			prepared.RecordBytes, digest, IngestVersion).Scan(&sourceRecordID)
		profile.SourceSQL += time.Since(sqlStarted)
		if err != nil {
			return ordinal, fmt.Errorf("insert FI source record: %w", err)
		}
		var projectErr error
		if prepared.Record.RecordKind == "WindowsSecurityCoverage" {
			projectErr = profile.coverageBuffer.add(ctx, tx, sourceRecordID, prepared)
		} else {
			projectStarted := time.Now()
			projectCtx := ctx
			if prepared.Record.RecordKind == "USNObjectObservation" {
				projectCtx = context.WithValue(ctx, fileObservationBulkBytesContextKey{}, prepared.RecordBytes)
			}
			projectErr = ProjectSourceRecord(projectCtx, tx, sourceID, sourceRecordID, prepared)
			profile.Projection += time.Since(projectStarted)
		}
		if projectErr != nil {
			return ordinal, fmt.Errorf("%w: batch %s record %d (%s): %v", ErrSourceRecordRejected, batch.BatchID, ordinal, prepared.Record.RecordKind, projectErr)
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return ordinal, fmt.Errorf("%w: batch %s ended without final LF", ErrSourceRecordRejected, batch.BatchID)
			}
			return ordinal, fmt.Errorf("read FI source batch: %w", readErr)
		}
	}
	if err := flushFiles(); err != nil {
		return ordinal, err
	}
	if err := flushSecurity(); err != nil {
		return ordinal, err
	}
	fileFlushStarted := time.Now()
	fileFlushErr := fileBulk.flush(ctx, tx)
	profile.Projection += time.Since(fileFlushStarted)
	if fileFlushErr != nil {
		return ordinal, fmt.Errorf("%w: batch %s FileObservation final bulk projection: %v", ErrSourceRecordRejected, batch.BatchID, fileFlushErr)
	}

	gotSHA := hex.EncodeToString(hasher.Sum(nil))
	if ordinal != int64(batch.Manifest.RecordCount) || byteCount != batch.Manifest.DataBytes || gotSHA != batch.Manifest.DataSHA256 {
		return ordinal, fmt.Errorf("%w: batch %s changed between custody validation and relational ingest", ErrSourceRecordRejected, batch.BatchID)
	}
	return ordinal, nil
}

func verifyGenerationProjectionCoverage(ctx context.Context, tx pgx.Tx, recordedGenerationID int64) error {
	var missing int64
	err := tx.QueryRow(ctx, `
SELECT count(*)
FROM fi.source_record sr
JOIN fi.source_batch sb ON sb.source_batch_id = sr.source_batch_id
WHERE sb.recorded_generation_id = $1
  AND CASE sr.record_kind
    WHEN 'CollectorIdentity' THEN NOT EXISTS (SELECT 1 FROM fi.collector_identity x WHERE x.source_record_id=sr.source_record_id)
    WHEN 'DirectoryPrincipalSnapshot' THEN NOT EXISTS (SELECT 1 FROM fi.directory_principal_snapshot x WHERE x.source_record_id=sr.source_record_id)
    WHEN 'FileObservation' THEN NOT EXISTS (SELECT 1 FROM fi.file_observation x WHERE x.source_record_id=sr.source_record_id)
    WHEN 'LocalPrincipalSnapshot' THEN NOT EXISTS (SELECT 1 FROM fi.local_principal_snapshot x WHERE x.source_record_id=sr.source_record_id)
    WHEN 'NTFSCollectionError' THEN NOT EXISTS (SELECT 1 FROM fi.ntfs_collection_error x WHERE x.source_record_id=sr.source_record_id)
    WHEN 'SMBShareSnapshot' THEN NOT EXISTS (SELECT 1 FROM fi.smb_share_snapshot x WHERE x.source_record_id=sr.source_record_id)
    WHEN 'SupportingSourceCollectionError' THEN NOT EXISTS (SELECT 1 FROM fi.supporting_source_collection_error x WHERE x.source_record_id=sr.source_record_id)
    WHEN 'USNContinuityGap' THEN NOT EXISTS (SELECT 1 FROM fi.usn_continuity_gap x WHERE x.source_record_id=sr.source_record_id)
    WHEN 'USNObjectObservation' THEN NOT EXISTS (SELECT 1 FROM fi.usn_object_observation x WHERE x.source_record_id=sr.source_record_id)
    WHEN 'USNReadBoundary' THEN NOT EXISTS (SELECT 1 FROM fi.usn_read_boundary x WHERE x.source_record_id=sr.source_record_id)
    WHEN 'WindowsSecurityContinuityGap' THEN NOT EXISTS (SELECT 1 FROM fi.windows_security_continuity_gap x WHERE x.source_record_id=sr.source_record_id)
    WHEN 'WindowsSecurityCoverage' THEN NOT EXISTS (SELECT 1 FROM fi.windows_security_coverage x WHERE x.source_record_id=sr.source_record_id)
    WHEN 'WindowsSecurityEvent' THEN NOT EXISTS (SELECT 1 FROM fi.windows_security_event x WHERE x.source_record_id=sr.source_record_id)
    ELSE true
  END
`, recordedGenerationID).Scan(&missing)
	if err != nil {
		return fmt.Errorf("verify FI relational projection coverage: %w", err)
	}
	if missing != 0 {
		return fmt.Errorf("%w: %d source records lack their typed relational projection", ErrSourceRecordRejected, missing)
	}
	return nil
}

func rejectIngestAttempt(ctx context.Context, connection *pgx.Conn, tx pgx.Tx, result IngestResult, cause error) error {
	rollbackErr := tx.Rollback(ctx)
	seen := result.RecordsSeen
	zero := int64(0)
	journalErr := WriteAttemptTerminal(ctx, connection, JournalEvent{
		AttemptID: result.AttemptID, SourceID: result.SourceID, GenerationID: result.GenerationID, TransferSHA256: result.TransferSHA256,
		Outcome: "Rejected", Stage: "AuthoritativeRecord", ReasonCode: "SOURCE_RECORD_REJECTED", Detail: cause.Error(), RecordsSeen: &seen, RecordsCommitted: &zero,
	})
	return errors.Join(cause, rollbackErr, journalErr)
}

func failIngestAttempt(ctx context.Context, connection *pgx.Conn, tx pgx.Tx, result IngestResult, stage, reason string, cause error) error {
	rollbackErr := tx.Rollback(ctx)
	seen := result.RecordsSeen
	zero := int64(0)
	outcome := "Failed"
	if errors.Is(cause, ErrGenerationConflict) {
		outcome = "Conflict"
		reason = "GENERATION_IDENTITY_CONFLICT"
	}
	journalErr := WriteAttemptTerminal(ctx, connection, JournalEvent{
		AttemptID: result.AttemptID, SourceID: result.SourceID, GenerationID: result.GenerationID, TransferSHA256: result.TransferSHA256,
		Outcome: outcome, Stage: stage, ReasonCode: reason, Detail: cause.Error(), RecordsSeen: &seen, RecordsCommitted: &zero,
	})
	return errors.Join(cause, rollbackErr, journalErr)
}

func bytesEqual(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var diff byte
	for i := range left {
		diff |= left[i] ^ right[i]
	}
	return diff == 0
}
