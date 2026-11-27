// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package recordingest

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

type m1RelationalFixture struct {
	GenerationID string
	SourceID     string
	Attempts     [2]string
}

func m1VerifyIsolatedPostgreSQL(
	t *testing.T,
	ctx context.Context,
	connection *pgx.Conn,
	root string,
	wantUser string,
) {
	t.Helper()

	// The ingest role must not need privileged PostgreSQL
	// configuration visibility to establish its session identity.
	// The administrator separately verifies the complete server
	// configuration and data directory before any fixture writes.
	if wantUser == "fi_ingest" {
		var sessionUser, sessionDB, sessionPort string
		var unixSocket bool

		err := connection.QueryRow(ctx, `
SELECT
    current_user,
    current_database(),
    current_setting('port'),
    inet_server_addr() IS NULL
`).Scan(
			&sessionUser,
			&sessionDB,
			&sessionPort,
			&unixSocket,
		)
		if err != nil {
			t.Fatalf(
				"verify unprivileged FI ingest session: %v",
				err,
			)
		}

		if sessionUser != "fi_ingest" ||
			sessionDB != "fi" ||
			sessionPort != "55418" ||
			!unixSocket {
			t.Fatalf(
				"STOP: ingest session isolation mismatch: user=%q db=%q port=%q unix_socket=%v",
				sessionUser,
				sessionDB,
				sessionPort,
				unixSocket,
			)
		}

		return
	}

	// Only the isolated fixture administrator examines
	// restricted PostgreSQL postmaster configuration.
	var user, database, directory, listen, port string

	err := connection.QueryRow(ctx, `
SELECT
    current_user,
    current_database(),
    current_setting('data_directory'),
    current_setting('listen_addresses'),
    current_setting('port')
`).Scan(&user, &database, &directory, &listen, &port)

	if err != nil {
		t.Fatal(err)
	}

	if user != wantUser ||
		database != "fi" ||
		directory != filepath.Join(root, "data") ||
		listen != "" ||
		port != "55418" {
		t.Fatalf(
			"STOP: database isolation failure: user=%q database=%q directory=%q listen=%q port=%q",
			user, database, directory, listen, port,
		)
	}
}

func m1CleanupRelationalFixtures(
	t *testing.T,
	admin *pgx.Conn,
	fixtures []m1RelationalFixture,
) {
	t.Helper()

	ctx, cancel := context.WithTimeout(
		context.Background(), 15*time.Second,
	)
	defer cancel()

	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Errorf("begin isolated fixture cleanup: %v", err)
		return
	}
	defer tx.Rollback(context.Background())

	statements := []string{
		`DELETE FROM fi.supporting_source_collection_error AS p
         USING fi.source_record AS sr,
               fi.source_batch AS sb,
               fi.recorded_generation AS rg
         WHERE p.source_record_id = sr.source_record_id
           AND sr.source_batch_id = sb.source_batch_id
           AND sb.recorded_generation_id = rg.recorded_generation_id
           AND rg.source_id = $1
           AND rg.generation_id = $2`,

		`DELETE FROM fi.source_record AS sr
         USING fi.source_batch AS sb,
               fi.recorded_generation AS rg
         WHERE sr.source_batch_id = sb.source_batch_id
           AND sb.recorded_generation_id = rg.recorded_generation_id
           AND rg.source_id = $1
           AND rg.generation_id = $2`,

		`DELETE FROM fi.source_batch AS sb
         USING fi.recorded_generation AS rg
         WHERE sb.recorded_generation_id = rg.recorded_generation_id
           AND rg.source_id = $1
           AND rg.generation_id = $2`,

		`DELETE FROM fi.recorded_generation
         WHERE source_id = $1 AND generation_id = $2`,
	}

	for _, fixture := range fixtures {
		for _, statement := range statements {
			if _, err := tx.Exec(
				ctx, statement,
				fixture.SourceID, fixture.GenerationID,
			); err != nil {
				t.Errorf(
					"clean up %s/%s: %v",
					fixture.SourceID, fixture.GenerationID, err,
				)
				return
			}
		}

		for _, attempt := range fixture.Attempts {
			if _, err := tx.Exec(ctx, `
DELETE FROM fi.ingest_journal
WHERE attempt_id = $1
  AND source_id = $2
  AND generation_id = $3`,
				attempt,
				fixture.SourceID,
				fixture.GenerationID,
			); err != nil {
				t.Errorf("clean up journal %s: %v", attempt, err)
				return
			}
		}
	}

	if err := tx.Commit(ctx); err != nil {
		t.Errorf("commit isolated fixture cleanup: %v", err)
		return
	}

	t.Log("PASS: All isolated ingest fixture rows cleaned")
}

func TestM1TwoSourceRelationalIngestRoundTrip(t *testing.T) {
	root := os.Getenv("FI_M1_TEST_POSTGRES_ROOT")

	expected := filepath.Join(
		os.Getenv("HOME"),
		"fi-m1-postgres-20261012",
	)

	if os.Getenv("FI_M1_ALLOW_ISOLATED_WRITES") != "1" {
		t.Skip("isolated PostgreSQL writes not enabled")
	}
	if root != expected {
		t.Fatalf("STOP: unexpected PostgreSQL root %q", root)
	}

	version, err := os.ReadFile(
		filepath.Join(root, "data", "PG_VERSION"),
	)
	if err != nil || string(version) != "18\n" {
		t.Fatal("STOP: isolated PostgreSQL 18 not verified")
	}

	ctx, cancel := context.WithTimeout(
		context.Background(), 90*time.Second,
	)
	defer cancel()

	connect := func(user string) string {
		return fmt.Sprintf(
			"host=%s port=55418 user=%s dbname=fi sslmode=disable connect_timeout=3",
			filepath.Join(root, "socket"), user,
		)
	}

	admin, err := pgx.Connect(ctx, connect("fi_m1_admin"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = admin.Close(context.Background())
	})

	m1VerifyIsolatedPostgreSQL(
		t, ctx, admin, root, "fi_m1_admin",
	)

	runtime, state, err := OpenPostgreSQL(
		ctx, connect("fi_ingest"),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close(context.Background())

	m1VerifyIsolatedPostgreSQL(
		t, ctx, runtime, root, "fi_ingest",
	)

	if state.RelationalTables != 49 {
		t.Fatalf(
			"unexpected relational schema: %d tables",
			state.RelationalTables,
		)
	}

	fixtureRoot := t.TempDir()

	for _, name := range []string{
		"custody", "recorded", "ready",
		"recorded/sources",
		"recorded/sources/iss-fs-2019.iss.local",
		"recorded/sources/iss-fs-22.iss.local",
	} {
		if err := os.Mkdir(
			filepath.Join(fixtureRoot, name), 0700,
		); err != nil {
			t.Fatal(err)
		}
	}

	sourceIDs := []string{
		"iss-fs-2019.iss.local",
		"iss-fs-22.iss.local",
	}

	fixtures := make([]m1RelationalFixture, 0, 2)

	// Create both authenticated, signed, durable generation fixtures
	// before performing any PostgreSQL mutation.
	signedSources := make([]m1SignedSource, 0, 2)

	for _, sourceID := range sourceIDs {
		signed := m1WriteSignedGeneration(
			t, fixtureRoot, sourceID,
		)
		signedSources = append(signedSources, signed)

		fixtures = append(fixtures, m1RelationalFixture{
			SourceID:     sourceID,
			GenerationID: signed.GenerationID,
			Attempts: [2]string{
				"m1-accepted-" + signed.GenerationID,
				"m1-replay-" + signed.GenerationID,
			},
		})
	}

	// Registered after the admin close handler so cleanup executes
	// first, including when a later test assertion fails.
	t.Cleanup(func() {
		m1CleanupRelationalFixtures(t, admin, fixtures)
	})

	for index, signed := range signedSources {
		fixture := fixtures[index]

		config := GenerationLoadConfig{
			CustodyRoot:       filepath.Join(fixtureRoot, "custody"),
			RecordedRoot:      filepath.Join(fixtureRoot, "recorded"),
			SourceNamespaces:  true,
			SourceID:          signed.SourceID,
			MaxCanonicalBytes: 64 << 20,
			MaxEncodedBytes:   64 << 20,
			MaxManifestBytes:  1 << 20,
		}

		prepared, err := loadRecordedGenerationWithTrust(
			config,
			signed.GenerationID,
			func(requested string) (generationTrustBundle, error) {
				if requested != signed.SourceID {
					return generationTrustBundle{},
						fmt.Errorf("wrong requested source: %q", requested)
				}
				return signed.Trust, nil
			},
		)
		if err != nil {
			t.Fatal(err)
		}

		if prepared.Receipt.Descriptor.SourceID != signed.SourceID ||
			len(prepared.Batches) != 1 ||
			prepared.Receipt.RecordCount != 1 {
			_ = prepared.Close()
			t.Fatal("loaded signed generation identity mismatch")
		}

		if err := WriteAttemptStarted(
			ctx, runtime, fixture.Attempts[0],
			signed.SourceID, signed.GenerationID,
		); err != nil {
			_ = prepared.Close()
			t.Fatal(err)
		}

		accepted, ingestErr := IngestPreparedGeneration(
			ctx, runtime, fixture.Attempts[0], prepared,
		)
		closeErr := prepared.Close()

		if ingestErr != nil {
			t.Fatal(ingestErr)
		}
		if closeErr != nil {
			t.Fatal(closeErr)
		}

		if accepted.Outcome != "Accepted" ||
			accepted.RecordsSeen != 1 ||
			accepted.RecordsCommitted != 1 ||
			accepted.RecordedGenerationID <= 0 {
			t.Fatalf("generation not committed: %+v", accepted)
		}

		var receiptSHA, transferSHA string

		err = runtime.QueryRow(ctx, `
SELECT
    encode(receipt_sha256,'hex'),
    encode(transfer_sha256,'hex')
FROM fi.recorded_generation
WHERE source_id=$1 AND generation_id=$2`,
			signed.SourceID, signed.GenerationID,
		).Scan(&receiptSHA, &transferSHA)

		if err != nil {
			t.Fatal(err)
		}

		if receiptSHA != accepted.ReceiptSHA256 ||
			transferSHA != accepted.TransferSHA256 {
			t.Fatal("authoritative generation digest mismatch")
		}

		var batchCount, recordCount, projectionCount int64

		err = runtime.QueryRow(ctx, `
SELECT
    count(DISTINCT sb.source_batch_id),
    count(DISTINCT sr.source_record_id),
    count(DISTINCT p.source_record_id)
FROM fi.recorded_generation AS rg
LEFT JOIN fi.source_batch AS sb
  ON sb.recorded_generation_id=rg.recorded_generation_id
LEFT JOIN fi.source_record AS sr
  ON sr.source_batch_id=sb.source_batch_id
LEFT JOIN fi.supporting_source_collection_error AS p
  ON p.source_record_id=sr.source_record_id
WHERE rg.source_id=$1 AND rg.generation_id=$2`,
			signed.SourceID, signed.GenerationID,
		).Scan(&batchCount, &recordCount, &projectionCount)

		if err != nil {
			t.Fatal(err)
		}

		if batchCount != 1 ||
			recordCount != 1 ||
			projectionCount != 1 {
			t.Fatalf(
				"%s relational counts batch=%d record=%d projection=%d",
				signed.SourceID,
				batchCount, recordCount, projectionCount,
			)
		}

		if err := WriteAttemptStarted(
			ctx, runtime, fixture.Attempts[1],
			signed.SourceID, signed.GenerationID,
		); err != nil {
			t.Fatal(err)
		}

		// Reopen immutable custody and receipt, not the prior staged
		// generation, for the idempotent ingest attempt.
		replay, err := loadRecordedGenerationWithTrust(
			config,
			signed.GenerationID,
			func(requested string) (generationTrustBundle, error) {
				if requested != signed.SourceID {
					return generationTrustBundle{},
						fmt.Errorf("wrong replay source %q", requested)
				}
				return signed.Trust, nil
			},
		)
		if err != nil {
			t.Fatal(err)
		}

		repeated, replayErr := IngestPreparedGeneration(
			ctx, runtime, fixture.Attempts[1], replay,
		)
		closeErr = replay.Close()

		if replayErr != nil {
			t.Fatal(replayErr)
		}
		if closeErr != nil {
			t.Fatal(closeErr)
		}

		if repeated.Outcome != "AlreadyAccepted" ||
			repeated.RecordedGenerationID !=
				accepted.RecordedGenerationID ||
			repeated.RecordsCommitted != 0 {
			t.Fatalf(
				"idempotent replay failed: %+v",
				repeated,
			)
		}

		var firstOutcome, retryOutcome string
		var firstCommitted, retryCommitted int64

		err = runtime.QueryRow(ctx, `
SELECT outcome, records_committed
FROM fi.ingest_journal
WHERE attempt_id=$1 AND event_sequence=2`,
			fixture.Attempts[0],
		).Scan(&firstOutcome, &firstCommitted)
		if err != nil {
			t.Fatal(err)
		}

		err = runtime.QueryRow(ctx, `
SELECT outcome, records_committed
FROM fi.ingest_journal
WHERE attempt_id=$1 AND event_sequence=2`,
			fixture.Attempts[1],
		).Scan(&retryOutcome, &retryCommitted)
		if err != nil {
			t.Fatal(err)
		}

		if firstOutcome != "Accepted" ||
			firstCommitted != 1 ||
			retryOutcome != "AlreadyAccepted" ||
			retryCommitted != 0 {
			t.Fatal("journal acceptance/replay mismatch")
		}

		plan, err := PlanRecordedGenerationsForSource(
			ctx,
			runtime,
			config.RecordedRoot,
			signed.SourceID,
		)
		if err != nil {
			t.Fatal(err)
		}

		if plan.Discovered != 1 ||
			plan.Accepted != 1 ||
			plan.Pending != 0 ||
			plan.Conflict != 0 {
			t.Fatalf(
				"post-ingest reconciliation failed for %s: %+v",
				signed.SourceID, plan,
			)
		}

		t.Logf(
			"PASS: %s signed=true committed=1 projected=1 replay=AlreadyAccepted reconcile=Accepted",
			signed.SourceID,
		)
	}

	t.Log("PASS: Two distinct sources committed through validated custody")
}
