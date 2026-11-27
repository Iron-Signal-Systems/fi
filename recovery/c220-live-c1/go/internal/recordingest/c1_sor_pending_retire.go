//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Governed pending retirement never changes canonical FI. It is allowed only
// AFTER the exact immutable signed generation has a durable Accepted journal
// and canonical readback. All pending relations are retired in one transaction.
// Canonical history and original receiver custody are never truncated.
package recordingest

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/Iron-Signal-Systems/fi/go/internal/c1handoff"
	"github.com/jackc/pgx/v5"
)

// c1PendingRetireTables is built only from the governed 49-table allowlist
// plus the single control relation. No table name comes from a sender,
// receipt, environmental input or untrusted catalog record.
func c1PendingRetireTables() ([]string, error) {
	if len(bootstrapSoRTables) != 49 {
		return nil, errors.New("C1 pending retire: frozen canonical table count changed")
	}
	seen := make(map[string]bool, 50)
	names := make([]string, 0, 50)
	for _, table := range bootstrapSoRTables {
		if table == "" || table == "generation_control" || seen[table] {
			return nil, errors.New("C1 pending retire: invalid frozen relational table")
		}
		seen[table] = true
		names = append(names, pgx.Identifier{c1GovernedPendingSchema, table}.Sanitize())
	}
	names = append(names, pgx.Identifier{c1GovernedPendingSchema, "generation_control"}.Sanitize())
	return names, nil
}

// c1RetireAcceptedPendingTx is a single isolated fi-sor PostgreSQL
// transaction. Caller must use ONLY fi_c1_publisher on the local socket;
// that role has TRUNCATE for pending tables, never for canonical FI.
// It deliberately refuses unsigned/foreign pending data and *any* missing
// canonical Accepted proof. No data is removed until all SQL locks/proofs pass.
func c1RetireAcceptedPendingTx(ctx context.Context, tx pgx.Tx,
	source, generation, receiptSHA string) error {
	if ctx == nil || tx == nil || source == "" || generation == "" || !canonicalDigest(receiptSHA) {
		return errors.New("C1 pending retire: exact original signed identity required")
	}
	digest, err := hex.DecodeString(receiptSHA)
	if err != nil || len(digest) != 32 {
		return errors.New("C1 pending retire: malformed signed receipt")
	}
	var role string
	if err = tx.QueryRow(ctx, "SELECT current_user").Scan(&role); err != nil {
		return err
	}
	if role != c1PublisherRole {
		return errors.New("C1 pending retire: only dedicated fi-sor canonical publisher may retire")
	}
	all, err := c1PendingRetireTables()
	if err != nil {
		return err
	}
	tables, err := bootstrapListTables(ctx, tx, c1GovernedPendingSchema)
	if err != nil {
		return err
	}
	expected := make(map[string]bool, 50)
	for _, name := range bootstrapSoRTables {
		expected[name] = true
	}
	expected["generation_control"] = true
	if len(tables) != len(expected) {
		return errors.New("C1 pending retire: extra or missing relational tables")
	}
	for _, table := range tables {
		if !expected[table] {
			return fmt.Errorf("C1 pending retire: unapproved pending table %q", table)
		}
	}
	// No transaction can remove or replace the canonical acceptance while
	// the subsequent pending ACCESS EXCLUSIVE locks and readback execute.
	if _, err = tx.Exec(ctx, "LOCK TABLE fi.recorded_generation, fi.ingest_journal IN SHARE MODE"); err != nil {
		return fmt.Errorf("C1 pending retire: canonical acceptance lock: %w", err)
	}
	// Match remapper's canonical -> pending lock order. One operation locks
	// the full pending FK graph, preventing new workers or foreign metadata.
	allSQL := strings.Join(all, ", ")
	if _, err = tx.Exec(ctx, "LOCK TABLE "+allSQL+" IN ACCESS EXCLUSIVE MODE"); err != nil {
		return fmt.Errorf("C1 pending retire: exclusive pending lock: %w", err)
	}
	status, err := c1CanonicalStatusInSnapshot(ctx, tx, source, generation, receiptSHA)
	if err != nil || status != c1handoff.FinalAccepted {
		return fmt.Errorf("C1 pending retire: exact canonical Accepted proof absent: %v", err)
	}
	var pendingGenerations, pendingControls, pendingRecords, pendingBatches int64
	err = tx.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM fi_c1_pending.recorded_generation),
		(SELECT count(*) FROM fi_c1_pending.generation_control),
		(SELECT count(*) FROM fi_c1_pending.source_record),
		(SELECT count(*) FROM fi_c1_pending.source_batch)`).
		Scan(&pendingGenerations, &pendingControls, &pendingRecords, &pendingBatches)
	if err != nil {
		return err
	}
	if pendingControls == 0 && pendingGenerations == 0 &&
		pendingRecords == 0 && pendingBatches == 0 {
		// A previous exact retirement may already have committed, but do
		// not silently accept child tables with unbound typed data.
		for _, table := range bootstrapSoRTables {
			q := "SELECT EXISTS(SELECT 1 FROM " +
				pgx.Identifier{c1GovernedPendingSchema, table}.Sanitize() + ")"
			var nonempty bool
			if err = tx.QueryRow(ctx, q).Scan(&nonempty); err != nil {
				return err
			}
			if nonempty {
				return fmt.Errorf("C1 pending retire: orphan pending rows in %s", table)
			}
		}
		return nil
	}
	if pendingGenerations != 1 || pendingControls != 1 {
		return errors.New("C1 pending retire: unrelated or missing pending generation")
	}
	var storedSource, storedGeneration, state string
	var storedReceipt, storedTransfer, canonicalTransfer []byte
	var storedRecords, storedBatches, canonicalRecords, canonicalBatches int64
	err = tx.QueryRow(ctx, `SELECT p.source_id,p.generation_id,p.receipt_sha256,
		p.transfer_sha256,p.record_count,p.batch_count,c.state,
		fi.transfer_sha256,fi.record_count,fi.batch_count
		FROM fi_c1_pending.recorded_generation p
		JOIN fi_c1_pending.generation_control c
		  ON c.source_id=p.source_id AND c.generation_id=p.generation_id
		 AND c.receipt_sha256=p.receipt_sha256
		 AND c.transfer_sha256=p.transfer_sha256
		 AND c.record_count=p.record_count AND c.batch_count=p.batch_count
		JOIN fi.recorded_generation fi
		  ON fi.source_id=p.source_id AND fi.generation_id=p.generation_id`).
		Scan(&storedSource, &storedGeneration, &storedReceipt, &storedTransfer,
			&storedRecords, &storedBatches, &state, &canonicalTransfer,
			&canonicalRecords, &canonicalBatches)
	if err != nil {
		return fmt.Errorf("C1 pending retire: exact signed control/canonical join: %w", err)
	}
	if storedSource != source || storedGeneration != generation ||
		!bytes.Equal(storedReceipt, digest) ||
		!bytes.Equal(storedTransfer, canonicalTransfer) ||
		storedRecords <= 0 || storedBatches <= 0 ||
		storedRecords != canonicalRecords || storedBatches != canonicalBatches ||
		storedRecords != pendingRecords || storedBatches != pendingBatches ||
		state == "Retired" {
		return errors.New("C1 pending retire: signed identity or SQL row counts differ from canonical Accepted")
	}
	if _, err = tx.Exec(ctx, "TRUNCATE TABLE "+allSQL+" CONTINUE IDENTITY RESTRICT"); err != nil {
		return fmt.Errorf("C1 pending retire: rollback-safe pending table retirement: %w", err)
	}
	return nil
}

// C1RetireAcceptedPending performs ONLY pending cleanup. The caller must
// independently establish original immutable receiver-custody evidence;
// the SQL transaction rechecks exact Accepted with canonical/pending locks.
// On commit failure the outcome is unknown and must be checked read-only.
func C1RetireAcceptedPending(ctx context.Context, publisherDSN,
	source, generation, receiptSHA string) error {
	if ctx == nil || source == "" || generation == "" || !canonicalDigest(receiptSHA) {
		return errors.New("C1 pending retire: original signed identity required")
	}
	conn, err := openC1SoRLocalPublisherSQL(ctx, publisherDSN)
	if err != nil {
		return err
	}
	defer conn.Close(context.Background())
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())
	if _, err = tx.Exec(ctx, "SET LOCAL lock_timeout = '5s'"); err != nil {
		return err
	}
	if err = c1RetireAcceptedPendingTx(ctx, tx, source, generation, receiptSHA); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("C1 pending retire: commit unknown; reconcile canonical/pending read-only before retry: %w", err)
	}
	fmt.Printf("FI C1 PENDING RETIRED source=%s generation=%s canonical_unchanged=true original_custody_preserved=true\n",
		source, generation)
	return nil
}

// c1RetirePreviouslyAcceptedPending handles a crash after canonical Accepted
// but before the transport ACK or pending retirement. This runs while the
// fi-sor singleton is already held; it does not mutate a generation whose
// canonical Accepted status cannot be proved from ORIGINAL receiver custody.
func (s *C1SoRService) c1RetirePreviouslyAcceptedPending(ctx context.Context) error {
	if s == nil || ctx == nil {
		return errors.New("C1 pending retire: missing fi-sor context")
	}
	if err := s.pendingLockHealthy(ctx); err != nil {
		return err
	}
	conn, _, err := openC1SoRLocalSQL(ctx, s.DSN, "")
	if err != nil {
		return err
	}
	defer conn.Close(context.Background())
	var count int64
	if err = conn.QueryRow(ctx, "SELECT count(*) FROM fi_c1_pending.generation_control").
		Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		return nil
	}
	if count != 1 {
		return errors.New("C1 pending retire: multiple or corrupt control records")
	}
	var source, generation string
	var receipt []byte
	if err = conn.QueryRow(ctx, `SELECT source_id,generation_id,receipt_sha256
		FROM fi_c1_pending.generation_control`).Scan(&source, &generation, &receipt); err != nil {
		return err
	}
	if len(receipt) != 32 {
		return errors.New("C1 pending retire: malformed custody receipt in control")
	}
	receiptSHA := hex.EncodeToString(receipt)
	frame := c1handoff.Frame{
		Kind: c1handoff.Status, Sequence: 1,
		SourceID: source, GenerationID: generation, ReceiptSHA256: receiptSHA,
	}
	// This checks receiver ORIGINAL recorded receipt and canonical
	// accepted generation/journal. It does not trust the pending control.
	status, err := C1OriginalSignedStatus(ctx, s.DSN, s.NativeBCustody, frame)
	if err != nil {
		return fmt.Errorf("C1 pending retire: original custody or canonical readback failed: %w", err)
	}
	if status != c1handoff.FinalAccepted {
		// Unaccepted partial SQL must remain untouched for exact replay.
		return nil
	}
	if err = C1RetireAcceptedPending(ctx, s.PublisherDSN,
		source, generation, receiptSHA); err != nil {
		return fmt.Errorf("C1 pending retire: accepted generation retained for reconciliation: %w", err)
	}
	return nil
}
