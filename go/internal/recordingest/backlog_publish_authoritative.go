// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// PublishVerifiedBacklogWithAuthoritativeIngest is the smallest safe bridge
// from fully verified PRIVATE recovery into the existing authoritative FI
// ingestion transaction. Only a caller holding an independently authenticated
// PreparedGeneration from FI's trust-checked custody loader may invoke it.
//
// It intentionally REPLAYS the original source batches through the canonical
// ingester: it does not copy private table IDs, swap schemas, or expose partial
// staged rows. Its cost is one full canonical generation transaction, so it is
// not the final bounded-promotion mechanism for a very large generation.
//
// The canonical ingester alone owns the Accepted journal entry and writes it
// atomically with all 49 relational tables. A failed verification has no
// authoritative journal side effects.
func PublishVerifiedBacklogWithAuthoritativeIngest(
	ctx context.Context,
	verificationConn, canonicalConn *pgx.Conn,
	generation *PreparedGeneration,
	limits BacklogWindowLimits,
	attemptID string,
) (IngestResult, error) {
	if ctx == nil || verificationConn == nil || canonicalConn == nil ||
		verificationConn == canonicalConn || generation == nil || attemptID == "" {
		return IngestResult{}, errors.New("FI backlog publish: distinct connections, authenticated generation, attempt required")
	}
	if err := ctx.Err(); err != nil {
		return IngestResult{}, err
	}

	// An exact matching canonical generation is already an atomic commit.
	// Do not start another attempt, mutate a journal, or call private verifier
	// after the generation has become authoritative. Conflicting custody is
	// never considered an accepted retry.
	desc := generation.Receipt.Descriptor
	var storedTransfer, storedReceipt []byte
	var existingID int64
	err := verificationConn.QueryRow(ctx, `
SELECT recorded_generation_id,transfer_sha256,receipt_sha256
FROM fi.recorded_generation WHERE source_id=$1 AND generation_id=$2
`, desc.SourceID, desc.GenerationID).Scan(&existingID, &storedTransfer, &storedReceipt)
	if err == nil {
		wantTransfer, err := decodeHex(generation.Receipt.TransferSHA256, 32, true, "backlog.publish.transfer_sha256")
		if err != nil {
			return IngestResult{}, err
		}
		wantReceipt, err := decodeHex(generation.ReceiptSHA256, 32, true, "backlog.publish.receipt_sha256")
		if err != nil {
			return IngestResult{}, err
		}
		if !bytesEqual(storedTransfer, wantTransfer) || !bytesEqual(storedReceipt, wantReceipt) {
			return IngestResult{}, ErrGenerationConflict
		}
		return IngestResult{
			AttemptID: attemptID, SourceID: desc.SourceID, GenerationID: desc.GenerationID,
			TransferSHA256: generation.Receipt.TransferSHA256, ReceiptSHA256: generation.ReceiptSHA256,
			Batches: len(generation.Batches), DataBytes: generation.Receipt.DataBytes,
			RecordsSeen:          int64(generation.Receipt.RecordCount),
			RecordedGenerationID: existingID, Outcome: "AlreadyAccepted",
		}, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return IngestResult{}, fmt.Errorf("FI backlog publish: authoritative identity check: %w", err)
	}

	verified, err := VerifyCompleteBacklogTypedGeneration(ctx, verificationConn, generation, limits)
	if err != nil {
		return IngestResult{}, fmt.Errorf("FI backlog publish: incomplete or mismatched private recovery: %w", err)
	}
	if verified.Records != generation.Receipt.RecordCount ||
		verified.DataBytes != generation.Receipt.DataBytes ||
		verified.SourceID != desc.SourceID ||
		verified.GenerationID != desc.GenerationID ||
		verified.ReceiptSHA256 != generation.ReceiptSHA256 {
		return IngestResult{}, errors.New("FI backlog publish: verification result disagrees with signed custody")
	}

	// The existing canonical ingester re-reads and hashes the ORIGINAL source
	// batch files, validates every typed record, and atomically commits the
	// generation with its Accepted journal event. Never treat the private
	// verifier as authorization to copy mutable SQL rows into canonical fi.
	if err := WriteAttemptStarted(ctx, canonicalConn, attemptID, desc.SourceID, desc.GenerationID); err != nil {
		return IngestResult{}, fmt.Errorf("FI backlog publish: journal start: %w", err)
	}
	result, err := IngestPreparedGeneration(ctx, canonicalConn, attemptID, generation)
	if err != nil {
		return result, err
	}
	if result.Outcome != "Accepted" && result.Outcome != "AlreadyAccepted" {
		return result, fmt.Errorf("FI backlog publish: unexpected canonical outcome %q", result.Outcome)
	}
	if result.Outcome == "Accepted" &&
		(result.RecordsCommitted != int64(verified.Records) ||
			result.DataBytes != verified.DataBytes) {
		return result, errors.New("FI backlog publish: canonical accepted count mismatch")
	}
	return result, nil
}
