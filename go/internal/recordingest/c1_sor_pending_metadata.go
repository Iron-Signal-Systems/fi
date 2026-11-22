//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Signed-metadata admission into the governed pending PostgreSQL namespace.
// This uses the existing original Source of Record generation/batch SQL
// projectors and does NOT install a schema, activate the service, or publish
// to canonical fi. Pending data are durable and remain invisible to fi.
package recordingest

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/Iron-Signal-Systems/fi/go/internal/c1handoff"
	"github.com/jackc/pgx/v5"
)

// StageC1SignedPendingMetadata is the clean-generation, single-transaction
// admission primitive. It must not be invoked by fi-ingest, nor used as a
// restart replay shortcut. Incomplete/unknown SQL state stays quarantined.
func StageC1SignedPendingMetadata(ctx context.Context, dsn string,
	start c1handoff.Frame, custody c1NativeBCustodyConfig) error {
	if ctx == nil || start.Kind != c1handoff.Start || start.StartBatchIndex != 0 {
		return errors.New("C1 pending: only a new authenticated signed Start is admissible")
	}
	if err := start.Validate(); err != nil {
		return err
	}
	// Original receiver custody, not the client, determines source, batches,
	// signed identities and every expected record. Read it before SQL writes.
	original, err := c1StreamOriginalSignedManifestPlan(ctx,
		start.SourceID, start.GenerationID, custody)
	if err != nil {
		return fmt.Errorf("C1 pending: original signed custody preflight: %w", err)
	}
	conn, _, err := openC1SoRLocalSQL(ctx, dsn, "")
	if err != nil { return err }
	defer conn.Close(context.Background())
	return c1StageVerifiedPendingMetadata(ctx, conn, start, original)
}

// c1StageVerifiedPendingMetadata owns only the same signed-identity check
// and atomic SQL admission as the live fi-sor path. The production caller
// MUST first reauthenticate original receiver custody; an untrusted caller
// cannot reach this unexported primitive from the inter-jail protocol.
// Disposable PostgreSQL 18 tests invoke it with a separately authenticated
// original signed receiver fixture.
func c1StageVerifiedPendingMetadata(ctx context.Context, conn *pgx.Conn,
	start c1handoff.Frame, original *PreparedGeneration) error {
	if ctx == nil || conn == nil || start.Kind != c1handoff.Start || start.StartBatchIndex != 0 {
		return errors.New("C1 pending: only a new signed generation can enter a local SQL transaction")
	}
	if err := start.Validate(); err != nil { return err }
	if original == nil ||
		original.Receipt.Descriptor.SourceID != start.SourceID ||
		original.Receipt.Descriptor.GenerationID != start.GenerationID ||
		original.ReceiptSHA256 != start.ReceiptSHA256 ||
		int64(original.Receipt.RecordCount) != start.ExpectedRecords ||
		len(original.Batches) != len(start.BatchIDs) {
		return errors.New("C1 pending: original receiver receipt differs from signed Start")
	}
	for i, batch := range original.Batches {
		if batch.BatchID != start.BatchIDs[i] {
			return fmt.Errorf("C1 pending: signed batch roster changed at index %d", i)
		}
	}
	receiptDigest, err := hex.DecodeString(start.ReceiptSHA256)
	if err != nil || len(receiptDigest) != 32 {
		return errors.New("C1 pending: invalid exact recorded receipt digest")
	}
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())
	// Global serialization matches the deliberately single-unresolved
	// governed pending generation index; it cannot be scoped by receipt SHA.
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1::bigint)",
		int64(0x4631433150454e44)); err != nil {
		return err
	}
	var alreadyCanonical bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1 FROM fi.recorded_generation WHERE source_id=$1
		AND generation_id=$2)`, start.SourceID, start.GenerationID).
		Scan(&alreadyCanonical); err != nil {
		return err
	}
	if alreadyCanonical {
		return errors.New("C1 pending: canonical generation already exists; reconcile Accepted status")
	}
	// No old pending generation, even Retired, may be silently mixed into
	// the next SQL processing session. Clearing old typed rows requires a
	// separate verified retention/cleanup design, not an automatic TRUNCATE.
	tables, err := bootstrapListTables(ctx, tx, c1GovernedPendingSchema)
	if err != nil {
		return err
	}
	if len(tables) < 40 {
		return errors.New("C1 pending: governed full relational schema is not installed")
	}
	for _, table := range tables {
		name := pgx.Identifier{c1GovernedPendingSchema, table}.Sanitize()
		var hasRows bool
		if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM "+name+")").
			Scan(&hasRows); err != nil {
			return err
		}
		if hasRows {
			return fmt.Errorf("C1 pending: %s contains unreconciled rows; no automatic discard", table)
		}
	}
	var controlRows int64
	if err = tx.QueryRow(ctx,
		"SELECT count(*) FROM fi_c1_pending.generation_control").
		Scan(&controlRows); err != nil {
		return err
	}
	if controlRows != 0 {
		return errors.New("C1 pending: an existing generation control must be reconciled")
	}
	ids, err := c1StageOriginalPendingLedgerTx(ctx, tx, original)
	if err != nil {
		return err
	}
	// INSERT is column-restricted in PostgreSQL: fi_ingest cannot specify
	// state, verifier_b_at or verifier_b_receipt_sha256. The default is
	// Pending, and the composite FK guarantees exact signed SQL metadata.
	tag, err := tx.Exec(ctx, `INSERT INTO fi_c1_pending.generation_control (
		source_id,generation_id,receipt_sha256,transfer_sha256,
		record_count,batch_count)
		SELECT source_id,generation_id,receipt_sha256,transfer_sha256,
			record_count,batch_count
		FROM fi_c1_pending.recorded_generation
		WHERE source_id=$1 AND generation_id=$2 AND receipt_sha256=$3`,
		start.SourceID, start.GenerationID, receiptDigest)
	if err != nil {
		return fmt.Errorf("C1 pending: atomic restricted admission: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return errors.New("C1 pending: signed control insert did not match one generation")
	}
	// Never elevate a Pending bootstrap to B proof or Accepted. Successful
	// completion records only an atomic metadata/control transaction.
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("C1 pending: admission COMMIT uncertain; read-only reconcile before retry: %w", err)
	}
	fmt.Printf("FI C1 PENDING SIGNED METADATA COMMIT source=%s generation=%s batches=%d records=%d state=Pending canonical_unchanged=true\n",
		start.SourceID, start.GenerationID, len(ids), start.ExpectedRecords)
	return nil
}
