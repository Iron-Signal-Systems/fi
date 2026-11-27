// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/recordingest"
	"github.com/jackc/pgx/v5"
)

func TestM1PostgreSQLBackedSourceConflictIsolation(t *testing.T) {
	root := os.Getenv("FI_M1_TEST_POSTGRES_ROOT")
	if root == "" {
		t.Skip("isolated M1 PostgreSQL fixture not requested")
	}

	expectedRoot := filepath.Join(
		os.Getenv("HOME"),
		"fi-m1-postgres-20261012",
	)
	if root != expectedRoot {
		t.Fatalf("unexpected fixture root %q", root)
	}

	pgdata := filepath.Join(root, "data")
	socket := filepath.Join(root, "socket")

	version, err := os.ReadFile(filepath.Join(pgdata, "PG_VERSION"))
	if err != nil || strings.TrimSpace(string(version)) != "18" {
		t.Fatal("isolated PostgreSQL 18 data directory not verified")
	}

	ctx, cancel := context.WithTimeout(
		context.Background(),
		30*time.Second,
	)
	defer cancel()

	connectString := func(user string) string {
		return fmt.Sprintf(
			"host=%s port=55418 user=%s dbname=fi sslmode=disable connect_timeout=3",
			socket,
			user,
		)
	}

	admin, err := pgx.Connect(
		ctx,
		connectString("fi_m1_admin"),
	)
	if err != nil {
		t.Fatalf("connect fixture admin: %v", err)
	}

	var (
		currentUser     string
		currentDB       string
		dataDirectory   string
		listenAddresses string
		port            string
	)

	err = admin.QueryRow(ctx, `
SELECT
    current_user,
    current_database(),
    current_setting('data_directory'),
    current_setting('listen_addresses'),
    current_setting('port')
`).Scan(
		&currentUser,
		&currentDB,
		&dataDirectory,
		&listenAddresses,
		&port,
	)
	if err != nil {
		_ = admin.Close(context.Background())
		t.Fatalf("verify fixture identity: %v", err)
	}

	if currentUser != "fi_m1_admin" ||
		currentDB != "fi" ||
		dataDirectory != pgdata ||
		listenAddresses != "" ||
		port != "55418" {
		_ = admin.Close(context.Background())
		t.Fatalf(
			"fixture isolation mismatch: user=%q db=%q data=%q listen=%q port=%q",
			currentUser,
			currentDB,
			dataDirectory,
			listenAddresses,
			port,
		)
	}

	runtime, state, err := recordingest.OpenPostgreSQL(
		ctx,
		connectString("fi_ingest"),
	)
	if err != nil {
		_ = admin.Close(context.Background())
		t.Fatalf("open FI runtime PostgreSQL: %v", err)
	}
	defer func() {
		_ = runtime.Close(context.Background())
	}()

	if state.RelationalTables != 49 {
		_ = admin.Close(context.Background())
		t.Fatalf("relational tables=%d, want 49", state.RelationalTables)
	}

	const (
		sourceConflict = "m1-fixture-fs2019.local"
		sourceHealthy  = "m1-fixture-fs22.local"
	)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	conflictGeneration := "m1-conflict-" + suffix
	healthyGeneration := "m1-accepted-" + suffix
	pendingGeneration := "m1-pending-" + suffix
	attemptID := "m1-healthy-attempt-" + suffix

	type fixtureRow struct {
		sourceID       string
		generationID   string
		transferSHA256 string
		receiptSHA256  string
	}

	rows := []fixtureRow{
		{
			sourceConflict,
			conflictGeneration,
			strings.Repeat("22", 32),
			strings.Repeat("33", 32),
		},
		{
			sourceHealthy,
			healthyGeneration,
			strings.Repeat("55", 32),
			strings.Repeat("44", 32),
		},
	}

	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(
			context.Background(),
			10*time.Second,
		)
		defer cleanupCancel()

		_, err := admin.Exec(
			cleanupCtx,
			`DELETE FROM fi.ingest_journal WHERE attempt_id = $1`,
			attemptID,
		)
		if err != nil {
			t.Errorf("clean up fixture journal: %v", err)
		}

		for _, row := range rows {
			_, err := admin.Exec(
				cleanupCtx,
				`DELETE FROM fi.recorded_generation
                 WHERE source_id = $1 AND generation_id = $2`,
				row.sourceID,
				row.generationID,
			)
			if err != nil {
				t.Errorf(
					"clean up fixture generation %q: %v",
					row.generationID,
					err,
				)
			}
		}

		if err := admin.Close(cleanupCtx); err != nil {
			t.Errorf("close fixture administrator: %v", err)
		}
	})

	const insertGeneration = `
INSERT INTO fi.recorded_generation (
    receipt_version,
    descriptor_version,
    source_id,
    generation_id,
    canonical_version,
    data_encoding,
    artifact_count,
    source_bytes,
    canonical_bytes,
    canonical_sha256,
    encoded_data_bytes,
    encoded_data_sha256,
    metadata_bytes,
    metadata_sha256,
    transfer_bytes,
    transfer_sha256,
    batch_count,
    data_bytes,
    record_count,
    receipt_bytes,
    receipt_sha256,
    ingest_version
) VALUES (
    'fi-generation-recorded/0.1',
    'fi-generation-descriptor/0.1',
    $1,
    $2,
    'fi-generation-canonical/0.1',
    'zstd',
    2,
    200,
    200,
    decode(repeat('aa', 32), 'hex'),
    100,
    decode(repeat('bb', 32), 'hex'),
    10,
    decode(repeat('cc', 32), 'hex'),
    100,
    decode($3, 'hex'),
    1,
    100,
    5,
    500,
    decode($4, 'hex'),
    'm1-isolated-integration-test'
)`

	for _, row := range rows {
		_, err := admin.Exec(
			ctx,
			insertGeneration,
			row.sourceID,
			row.generationID,
			row.transferSHA256,
			row.receiptSHA256,
		)
		if err != nil {
			t.Fatalf("insert synthetic fixture generation: %v", err)
		}
	}

	conflictCandidate := recordingest.RecordedReceiptCandidate{
		SourceID:       sourceConflict,
		GenerationID:   conflictGeneration,
		TransferSHA256: strings.Repeat("22", 32),
		ReceiptSHA256:  strings.Repeat("11", 32),
		BatchCount:     1,
		DataBytes:      100,
		RecordCount:    5,
	}

	healthyCandidate := recordingest.RecordedReceiptCandidate{
		SourceID:       sourceHealthy,
		GenerationID:   healthyGeneration,
		TransferSHA256: strings.Repeat("55", 32),
		ReceiptSHA256:  strings.Repeat("44", 32),
		BatchCount:     1,
		DataBytes:      100,
		RecordCount:    5,
	}

	pendingCandidate := recordingest.RecordedReceiptCandidate{
		SourceID:       sourceHealthy,
		GenerationID:   pendingGeneration,
		TransferSHA256: strings.Repeat("77", 32),
		ReceiptSHA256:  strings.Repeat("66", 32),
		BatchCount:     1,
		DataBytes:      100,
		RecordCount:    5,
	}

	conflictPlan, err :=
		recordingest.PlanRecordedReceiptCandidatesForIngest(
			ctx,
			runtime,
			sourceConflict,
			[]recordingest.RecordedReceiptCandidate{
				conflictCandidate,
			},
		)
	if err != nil {
		t.Fatalf("plan conflicting source: %v", err)
	}

	if conflictPlan.Conflict != 1 ||
		conflictPlan.Accepted != 0 ||
		conflictPlan.Pending != 0 {
		t.Fatalf("unexpected conflict plan: %+v", conflictPlan)
	}

	healthyPlan, err :=
		recordingest.PlanRecordedReceiptCandidatesForIngest(
			ctx,
			runtime,
			sourceHealthy,
			[]recordingest.RecordedReceiptCandidate{
				healthyCandidate,
				pendingCandidate,
			},
		)
	if err != nil {
		t.Fatalf("plan healthy source: %v", err)
	}

	if healthyPlan.Accepted != 1 ||
		healthyPlan.Pending != 1 ||
		healthyPlan.Conflict != 0 {
		t.Fatalf("unexpected healthy plan: %+v", healthyPlan)
	}

	var typedConflict *sourceReconcileConflictError
	if !errors.As(
		reconcileConflictError(conflictPlan),
		&typedConflict,
	) {
		t.Fatal("database reconciliation did not produce typed conflict")
	}

	if typedConflict.SourceID != sourceConflict ||
		typedConflict.GenerationID != conflictGeneration {
		t.Fatalf("typed conflict identity mismatch: %+v", typedConflict)
	}

	conflictState := sourceSessionState{
		Config: workerConfig{SourceID: sourceConflict},
		Repair: newRepairCadence(time.Hour),
	}

	healthyState := sourceSessionState{
		Config: workerConfig{SourceID: sourceHealthy},
		Repair: newRepairCadence(time.Hour),
	}

	conflictIngestCalls := 0

	err = runStartupSourcePlan(
		&conflictState,
		conflictPlan,
		func() error {
			conflictIngestCalls++
			return nil
		},
	)
	if err != nil {
		t.Fatalf("quarantine conflicting startup source: %v", err)
	}

	if !conflictState.Quarantined || conflictIngestCalls != 0 {
		t.Fatal("conflicting source was not isolated before ingest")
	}

	err = runStartupSourcePlan(
		&healthyState,
		healthyPlan,
		func() error {
			return recordingest.WriteAttemptStarted(
				ctx,
				runtime,
				attemptID,
				sourceHealthy,
				pendingGeneration,
			)
		},
	)
	if err != nil {
		t.Fatalf("healthy source startup continuation: %v", err)
	}

	if healthyState.Quarantined {
		t.Fatal("healthy source was incorrectly quarantined")
	}

	err = runScheduledSourcePass(
		&conflictState,
		func(*sourceSessionState) error {
			conflictIngestCalls++
			return nil
		},
	)
	if err != nil || conflictIngestCalls != 0 {
		t.Fatal("quarantined source resumed scheduled processing")
	}

	err = runScheduledSourcePass(
		&healthyState,
		func(*sourceSessionState) error {
			return recordingest.WriteAttemptTerminal(
				ctx,
				runtime,
				recordingest.JournalEvent{
					AttemptID:    attemptID,
					SourceID:     sourceHealthy,
					GenerationID: pendingGeneration,
					Outcome:      "Incomplete",
					Stage:        "M1FixtureContinuation",
					ReasonCode:   "M1_TEST_ONLY",
				},
			)
		},
	)
	if err != nil {
		t.Fatalf("healthy scheduled continuation: %v", err)
	}

	var journalCount int

	err = admin.QueryRow(ctx, `
SELECT count(*)
FROM fi.ingest_journal
WHERE attempt_id = $1
  AND source_id = $2
`, attemptID, sourceHealthy).Scan(&journalCount)

	if err != nil || journalCount != 2 {
		t.Fatalf(
			"healthy source journal rows=%d error=%v, want 2",
			journalCount,
			err,
		)
	}

	globalFailure := errors.New("synthetic global failure")

	err = runScheduledSourcePass(
		&healthyState,
		func(*sourceSessionState) error {
			return globalFailure
		},
	)

	if !errors.Is(err, globalFailure) {
		t.Fatalf("global failure incorrectly suppressed: %v", err)
	}

	if healthyState.Quarantined {
		t.Fatal("global error incorrectly quarantined healthy source")
	}

	t.Log("PASS: PostgreSQL detected FS2019 identity conflict")
	t.Log("PASS: FS2019 quarantined before ingest")
	t.Log("PASS: FS2019 scheduled processing suppressed")
	t.Log("PASS: FS22 accepted and pending identities independently resolved")
	t.Log("PASS: FS22 committed two append-only journal events")
	t.Log("PASS: Global failure propagated without source quarantine")
}
