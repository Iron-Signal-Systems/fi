//go:build freebsd && fi_copy_latency_replay_integration

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
	"github.com/jackc/pgx/v5"
)

const (
	securityReplaySource  = "iss-fs-22.iss.local"
	securityReplayFields  = 15
	securityReplayDefault = 1024
	securityReplayMaximum = 4096
)

// TestCopyLatencySecurityGenerationReplay measures the actual signed-custody,
// source-batch, event, scope, and event-field relational ingest paths. Its
// dedicated build tag prevents accidental execution during go test ./....
// No production services, recorded custody, or PostgreSQL data are used.
func TestCopyLatencySecurityGenerationReplay(t *testing.T) {
	if os.Getenv("FI_M1_ALLOW_ISOLATED_WRITES") != "1" {
		t.Skip("isolated PostgreSQL replay not enabled")
	}
	root := filepath.Join(os.Getenv("HOME"), "fi-m1-postgres-20261012")
	if os.Getenv("FI_M1_TEST_POSTGRES_ROOT") != root {
		t.Fatal("STOP: unexpected isolated PostgreSQL root")
	}
	version, err := os.ReadFile(filepath.Join(root, "data", "PG_VERSION"))
	if err != nil || string(version) != "18\n" {
		t.Fatal("STOP: isolated PostgreSQL 18 marker missing")
	}

	count := securityReplayDefault
	if value := os.Getenv("FI_COPY_LATENCY_SECURITY_RECORDS"); value != "" {
		count, err = strconv.Atoi(value)
		if err != nil || count < 1 || count > securityReplayMaximum {
			t.Fatal("FI_COPY_LATENCY_SECURITY_RECORDS must be 1..4096")
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
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
	t.Cleanup(func() { _ = admin.Close(context.Background()) })
	m1VerifyIsolatedPostgreSQL(t, ctx, admin, root, "fi_m1_admin")

	runtime, state, err := OpenPostgreSQL(ctx, connect("fi_ingest"))
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close(context.Background())
	m1VerifyIsolatedPostgreSQL(t, ctx, runtime, root, "fi_ingest")
	if state.RelationalTables != 49 {
		t.Fatalf("unexpected isolated relational schema: %d tables", state.RelationalTables)
	}

	fixtureRoot := t.TempDir()
	for _, part := range []string{
		"custody", "recorded", "ready",
		filepath.Join("recorded", "sources", securityReplaySource),
	} {
		if err := os.MkdirAll(filepath.Join(fixtureRoot, part), 0700); err != nil {
			t.Fatal(err)
		}
	}

	// Generate valid Windows Security 4663 observations, each with one matched
	// scope and 15 indexed event-field children. Exactly one signed generation
	// is used per test run; field cardinality is fixed for valid comparisons.
	now := time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z")
	input := make([]spool.Record, 0, count)
	for i := 0; i < count; i++ {
		fields := make([]records.WindowsSecurityEventField, 0, securityReplayFields)
		for j := 0; j < securityReplayFields; j++ {
			fields = append(fields, records.WindowsSecurityEventField{
				Name: fmt.Sprintf("Field%02d", j), Value: fmt.Sprintf("value-%02d", j),
			})
		}
		observation := records.WindowsSecurityEventObservation{
			ObservedAt:       now,
			CollectionMethod: records.WindowsSecurityCollectionMethod,
			Channel:          "Security",
			Provider:         "Microsoft-Windows-Security-Auditing",
			EventID:          "4663",
			EventRecordID:    strconv.Itoa(100000000 + i),
			TimeCreated:      now,
			Computer:         "fi-security-replay.iss.local",
			AuditResult:      records.WindowsSecurityAuditSuccess,
			ScopeBasis:       records.WindowsSecurityScopePathMatched,
			MatchedScopes: []records.WindowsSecurityMatchedScope{
				{ScopeID: "security-replay", GovernedRoot: `C:\FI-Latency-Test`},
			},
			Fields: fields,
			RawXML: fmt.Sprintf("<Event><RecordID>%d</RecordID></Event>", i),
		}
		if err := records.ValidateWindowsSecurityEventObservation(observation); err != nil {
			t.Fatalf("invalid security fixture %d: %v", i, err)
		}
		payload, err := json.Marshal(observation)
		if err != nil {
			t.Fatal(err)
		}
		input = append(input, spool.Record{
			Version:    spool.RecordVersion,
			RecordKind: "WindowsSecurityEvent",
			ScopeID:    "security-replay",
			WrittenAt:  now,
			Payload:    payload,
		})
	}

	// m1WriteSignedGenerationRecords is a test-only extension of the existing
	// authenticated generation fixture. It publishes into t.TempDir custody.
	signed := m1WriteSignedGenerationRecords(t, fixtureRoot, securityReplaySource, input)
	attemptID := "copy-latency-security-" + signed.GenerationID
	t.Cleanup(func() {
		cleanupSecurityReplay(t, admin, securityReplaySource, signed.GenerationID, attemptID)
	})

	config := GenerationLoadConfig{
		CustodyRoot:       filepath.Join(fixtureRoot, "custody"),
		RecordedRoot:      filepath.Join(fixtureRoot, "recorded"),
		SourceNamespaces:  true,
		SourceID:          securityReplaySource,
		MaxCanonicalBytes: 64 << 20,
		MaxEncodedBytes:   64 << 20,
		MaxManifestBytes:  1 << 20,
	}
	prepared, err := loadRecordedGenerationWithTrust(config, signed.GenerationID,
		func(source string) (generationTrustBundle, error) {
			if source != securityReplaySource {
				return generationTrustBundle{}, fmt.Errorf("unexpected fixture source %q", source)
			}
			return signed.Trust, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	if prepared.Receipt.RecordCount != uint64(count) || len(prepared.Batches) != 1 {
		t.Fatal("signed replay receipt does not match generated record count")
	}
	if err := WriteAttemptStarted(ctx, runtime, attemptID, securityReplaySource, signed.GenerationID); err != nil {
		t.Fatal(err)
	}

	started := time.Now()
	result, err := IngestPreparedGeneration(ctx, runtime, attemptID, prepared)
	elapsed := time.Since(started)
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != "Accepted" || result.RecordsSeen != int64(count) ||
		result.RecordsCommitted != int64(count) {
		t.Fatalf("unexpected committed replay result: %+v", result)
	}

	var events, scopes, fields int64
	err = admin.QueryRow(ctx, `
SELECT
    count(DISTINCT e.source_record_id),
    (SELECT count(*) FROM fi.windows_security_event_scope s
       JOIN fi.windows_security_event e2 USING (source_record_id)
       JOIN fi.source_record sr USING (source_record_id)
       JOIN fi.source_batch sb USING (source_batch_id)
       JOIN fi.recorded_generation rg USING (recorded_generation_id)
       WHERE rg.source_id=$1 AND rg.generation_id=$2),
    (SELECT count(*) FROM fi.windows_security_event_field f
       JOIN fi.windows_security_event e2 USING (source_record_id)
       JOIN fi.source_record sr USING (source_record_id)
       JOIN fi.source_batch sb USING (source_batch_id)
       JOIN fi.recorded_generation rg USING (recorded_generation_id)
       WHERE rg.source_id=$1 AND rg.generation_id=$2)
FROM fi.windows_security_event e
JOIN fi.source_record sr USING (source_record_id)
JOIN fi.source_batch sb USING (source_batch_id)
JOIN fi.recorded_generation rg USING (recorded_generation_id)
WHERE rg.source_id=$1 AND rg.generation_id=$2`,
		securityReplaySource, signed.GenerationID).Scan(&events, &scopes, &fields)
	if err != nil {
		t.Fatal(err)
	}
	if events != int64(count) || scopes != int64(count) ||
		fields != int64(count*securityReplayFields) {
		t.Fatalf("replay projection mismatch: events=%d scopes=%d fields=%d", events, scopes, fields)
	}
	seconds := elapsed.Seconds()
	t.Logf("FI SECURITY REPLAY ACCEPTED records=%d scopes=%d fields=%d elapsed=%s rate=%.1f_records_per_second",
		count, scopes, fields, elapsed.Round(time.Millisecond), float64(count)/seconds)
	t.Log("Observe INGEST COPY LATENCY SECURITY and INGEST PROFILE above for per-COPY and stage timings")
}

// cleanupSecurityReplay removes only the uniquely identified generated rows.
// It is registered after the database-close cleanup, so cleanup runs first.
// If any delete fails, rollback retains the fixture for investigation, but
// only in the separately verified isolated test PostgreSQL cluster.
func cleanupSecurityReplay(t *testing.T, admin *pgx.Conn, sourceID, generationID, attemptID string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Errorf("begin replay cleanup: %v", err)
		return
	}
	defer tx.Rollback(context.Background())
	// Parents are removed only after all foreign-key children.
	for _, table := range []string{
		"windows_security_event_field",
		"windows_security_event_scope",
		"windows_security_event",
	} {
		statement := fmt.Sprintf(`DELETE FROM fi.%s AS child USING fi.source_record sr,
             fi.source_batch sb, fi.recorded_generation rg
             WHERE child.source_record_id=sr.source_record_id
               AND sr.source_batch_id=sb.source_batch_id
               AND sb.recorded_generation_id=rg.recorded_generation_id
               AND rg.source_id=$1 AND rg.generation_id=$2`, table)
		if _, err := tx.Exec(ctx, statement, sourceID, generationID); err != nil {
			t.Errorf("clean up %s: %v", table, err)
			return
		}
	}
	for _, statement := range []string{
		`DELETE FROM fi.source_record sr USING fi.source_batch sb, fi.recorded_generation rg
           WHERE sr.source_batch_id=sb.source_batch_id
             AND sb.recorded_generation_id=rg.recorded_generation_id
             AND rg.source_id=$1 AND rg.generation_id=$2`,
		`DELETE FROM fi.source_batch sb USING fi.recorded_generation rg
           WHERE sb.recorded_generation_id=rg.recorded_generation_id
             AND rg.source_id=$1 AND rg.generation_id=$2`,
		`DELETE FROM fi.recorded_generation WHERE source_id=$1 AND generation_id=$2`,
	} {
		if _, err := tx.Exec(ctx, statement, sourceID, generationID); err != nil {
			t.Errorf("clean up replay fixture: %v", err)
			return
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM fi.ingest_journal
        WHERE attempt_id=$1 AND source_id=$2 AND generation_id=$3`,
		attemptID, sourceID, generationID); err != nil {
		t.Errorf("clean up replay journal: %v", err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		t.Errorf("commit replay cleanup: %v", err)
		return
	}
	var leftover int64
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM fi.recorded_generation
        WHERE source_id=$1 AND generation_id=$2`, sourceID, generationID).Scan(&leftover); err != nil || leftover != 0 {
		t.Errorf("replay cleanup verification: remaining=%d err=%v", leftover, err)
		return
	}
	t.Log("PASS: isolated security replay fixture rows cleaned")
}
