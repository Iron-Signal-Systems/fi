//go:build freebsd && fi_copy_latency_replay_integration && fi_relational_index_ab_integration

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Isolated benchmark: signed FileObservation + WindowsSecurityEvent source
// records interleaved within ONE generation; the exact FI production ingest
// function and relational constraints are used. No production SoR connection.
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
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
	"github.com/jackc/pgx/v5"
)

const (
	indexABSource         = "fi-relational-index-ab.iss.local"
	indexABFileScope      = "fi-relational-index-ab-files"
	indexABSecurityScope  = "fi-relational-index-ab-security"
	indexABFieldsPerEvent = 15
	indexABFiles          = 2048
	indexABEvents         = 2048
)

// TestFIRelationalIndexABMixedGeneration is deliberately opt-in and restricted
// to the preexisting, verified 49-table M1 fixture. Both record families are
// interleaved in signed custody to exercise real projection dependencies.
func TestFIRelationalIndexABMixedGeneration(t *testing.T) {
	if os.Getenv("FI_M1_ALLOW_ISOLATED_WRITES") != "1" {
		t.Skip("explicit isolated write approval missing")
	}
	root := filepath.Join(os.Getenv("HOME"), "fi-m1-postgres-20261012")
	if os.Getenv("FI_M1_TEST_POSTGRES_ROOT") != root {
		t.Fatal("STOP: isolated PostgreSQL root mismatch")
	}
	version, err := os.ReadFile(filepath.Join(root, "data", "PG_VERSION"))
	if err != nil || string(version) != "18\n" {
		t.Fatal("STOP: PostgreSQL 18 fixture marker missing")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	connect := func(user string) string {
		return fmt.Sprintf("host=%s port=55418 user=%s dbname=fi sslmode=disable connect_timeout=3",
			filepath.Join(root, "socket"), user)
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
		t.Fatalf("STOP: FI table count %d != 49", state.RelationalTables)
	}

	// Never adopt or clean up a source from another test attempt. A leftover
	// generation/journal/volume must be manually reconciled before any retry.
	var generations, journals, volumes int64
	err = admin.QueryRow(ctx, `SELECT
      (SELECT count(*) FROM fi.recorded_generation WHERE source_id=$1),
      (SELECT count(*) FROM fi.ingest_journal WHERE source_id=$1),
      (SELECT count(*) FROM fi.ntfs_volume WHERE source_id=$1)`, indexABSource).
		Scan(&generations, &journals, &volumes)
	if err != nil {
		t.Fatal(err)
	}
	if generations != 0 || journals != 0 || volumes != 0 {
		t.Fatalf("STOP: source already present generations=%d journals=%d volumes=%d", generations, journals, volumes)
	}

	fixture := t.TempDir()
	for _, part := range []string{"custody", "recorded", "ready",
		filepath.Join("recorded", "sources", indexABSource)} {
		if err := os.MkdirAll(filepath.Join(fixture, part), 0700); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z")
	filesInput := make([]spool.Record, 0, indexABFiles)
	securityInput := make([]spool.Record, 0, indexABEvents)
	for i := 0; i < indexABFiles; i++ {
		file, err := fileReplayObservation(i, now)
		if err != nil {
			t.Fatalf("file %d: %v", i, err)
		}
		file.NTFS.GovernedRoot.ScopeID = indexABFileScope
		if err := ntfs.ValidateObservation(file.NTFS); err != nil {
			t.Fatalf("NTFS %d: %v", i, err)
		}
		payload, err := json.Marshal(file)
		if err != nil {
			t.Fatal(err)
		}
		filesInput = append(filesInput, spool.Record{
			Version: spool.RecordVersion, RecordKind: "FileObservation",
			ScopeID: indexABFileScope, WrittenAt: now, Payload: payload,
		})

		fields := make([]records.WindowsSecurityEventField, 0, indexABFieldsPerEvent)
		for j := 0; j < indexABFieldsPerEvent; j++ {
			fields = append(fields, records.WindowsSecurityEventField{
				Name: fmt.Sprintf("Field%02d", j), Value: fmt.Sprintf("value-%02d", j),
			})
		}
		event := records.WindowsSecurityEventObservation{
			ObservedAt:       now,
			CollectionMethod: records.WindowsSecurityCollectionMethod,
			Channel:          "Security", Provider: "Microsoft-Windows-Security-Auditing",
			EventID: "4663", EventRecordID: strconv.Itoa(200000000 + i),
			TimeCreated: now, Computer: "fi-index-ab.iss.local",
			AuditResult: records.WindowsSecurityAuditSuccess,
			ScopeBasis:  records.WindowsSecurityScopePathMatched,
			MatchedScopes: []records.WindowsSecurityMatchedScope{
				{ScopeID: indexABSecurityScope, GovernedRoot: `C:\FI-Index-AB`},
			},
			Fields: fields,
			RawXML: fmt.Sprintf("<Event><RecordID>%d</RecordID></Event>", i),
		}
		if err := records.ValidateWindowsSecurityEventObservation(event); err != nil {
			t.Fatalf("security event %d: %v", i, err)
		}
		payload, err = json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		securityInput = append(securityInput, spool.Record{
			Version: spool.RecordVersion, RecordKind: "WindowsSecurityEvent",
			ScopeID: indexABSecurityScope, WrittenAt: now, Payload: payload,
		})
	}
	// Keep the signed source order deterministic while avoiding unrealistic
	// one-record COPY flushes at every kind transition. Interleave bounded
	// 128-record runs of each source family inside one generation.
	input := make([]spool.Record, 0, indexABFiles+indexABEvents)
	const run = 128
	for offset := 0; offset < indexABFiles; offset += run {
		input = append(input, filesInput[offset:offset+run]...)
		input = append(input, securityInput[offset:offset+run]...)
	}
	// The existing FI signing fixture deliberately accepts at most 4,096
	// records in one generation. Fail here if this bound is ever changed.
	if len(input) != 4096 {
		t.Fatalf("mixed signed fixture must contain 4096 records, got %d", len(input))
	}
	signed := m1WriteSignedGenerationRecords(t, fixture, indexABSource, input)
	attemptID := "relational-index-ab-" + signed.GenerationID
	// Register cleanup after the admin connection has been opened. Cleanup
	// verifies exact source ownership and never truncates shared FI tables.
	t.Cleanup(func() { cleanupFIRelationalIndexAB(t, admin, signed.GenerationID, attemptID) })
	config := GenerationLoadConfig{
		CustodyRoot:      filepath.Join(fixture, "custody"),
		RecordedRoot:     filepath.Join(fixture, "recorded"),
		SourceNamespaces: true, SourceID: indexABSource,
		MaxCanonicalBytes: 128 << 20, MaxEncodedBytes: 128 << 20,
		MaxManifestBytes: 1 << 20,
	}
	prepared, err := loadRecordedGenerationWithTrust(config, signed.GenerationID,
		func(source string) (generationTrustBundle, error) {
			if source != indexABSource {
				return generationTrustBundle{}, fmt.Errorf("unexpected source %q", source)
			}
			return signed.Trust, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	if prepared.Receipt.RecordCount != uint64(len(input)) {
		t.Fatalf("signed custody count mismatch: %d != %d", prepared.Receipt.RecordCount, len(input))
	}
	if err := WriteAttemptStarted(ctx, runtime, attemptID, indexABSource, signed.GenerationID); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	result, err := IngestPreparedGeneration(ctx, runtime, attemptID, prepared)
	elapsed := time.Since(started)
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != "Accepted" || result.RecordsSeen != int64(len(input)) ||
		result.RecordsCommitted != int64(len(input)) {
		t.Fatalf("signed relational acceptance mismatch: %+v", result)
	}

	// Count child rows using the exact recorded-generation lineage; no global
	// COUNT(*) scan and no reliance on indexes under comparison.
	tables := []struct {
		name string
		want int64
	}{
		{"source_record", int64(len(input))},
		{"file_observation", indexABFiles},
		{"file_metadata_observation", indexABFiles},
		{"content_hash_observation", indexABFiles},
		{"windows_security_event", indexABEvents},
		{"windows_security_event_scope", indexABEvents},
		{"windows_security_event_field", indexABEvents * indexABFieldsPerEvent},
	}
	for _, item := range tables {
		q := fmt.Sprintf(`SELECT count(*) FROM fi.%s AS c
          JOIN fi.source_record sr USING (source_record_id)
          JOIN fi.source_batch sb USING (source_batch_id)
          JOIN fi.recorded_generation rg USING (recorded_generation_id)
          WHERE rg.source_id=$1 AND rg.generation_id=$2`, item.name)
		// source_record itself has source_record_id; other projection tables
		// inherit the same source_record_id foreign key.
		if item.name == "source_record" {
			q = `SELECT count(*) FROM fi.source_record sr
              JOIN fi.source_batch sb USING (source_batch_id)
              JOIN fi.recorded_generation rg USING (recorded_generation_id)
              WHERE rg.source_id=$1 AND rg.generation_id=$2`
		}
		var count int64
		if err := admin.QueryRow(ctx, q, indexABSource, signed.GenerationID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != item.want {
			t.Fatalf("table %s: got %d want %d", item.name, count, item.want)
		}
	}
	t.Logf("FI RELATIONAL INDEX AB ACCEPTED records=%d files=%d security_events=%d event_fields=%d elapsed=%s rate=%.1f_records_per_second",
		len(input), indexABFiles, indexABEvents, indexABEvents*indexABFieldsPerEvent,
		elapsed.Round(time.Millisecond), float64(len(input))/elapsed.Seconds())
}

// Cleanup is scoped exclusively to this reserved synthetic source and its
// signed generation. Delete FK children before parents; never TRUNCATE.
func cleanupFIRelationalIndexAB(t *testing.T, admin *pgx.Conn, generationID, attemptID string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Errorf("fixture cleanup begin: %v", err)
		return
	}
	defer tx.Rollback(context.Background())
	for _, table := range []string{
		"windows_security_event_field", "windows_security_event_scope", "windows_security_event",
		"stream_observation", "security_ace", "sacl_ace",
		"file_metadata_observation", "content_hash_observation",
		"content_prefix_observation", "reparse_observation", "stream_inventory",
		"security_observation", "sacl_observation", "observation_warning", "file_observation",
	} {
		query := fmt.Sprintf(`DELETE FROM fi.%s AS child USING
          fi.source_record sr, fi.source_batch sb, fi.recorded_generation rg
          WHERE child.source_record_id=sr.source_record_id
          AND sr.source_batch_id=sb.source_batch_id
          AND sb.recorded_generation_id=rg.recorded_generation_id
          AND rg.source_id=$1 AND rg.generation_id=$2`, table)
		if _, err := tx.Exec(ctx, query, indexABSource, generationID); err != nil {
			t.Errorf("fixture cleanup %s: %v", table, err)
			return
		}
	}
	for _, q := range []string{
		`DELETE FROM fi.source_record sr USING fi.source_batch sb, fi.recorded_generation rg
          WHERE sr.source_batch_id=sb.source_batch_id AND sb.recorded_generation_id=rg.recorded_generation_id
            AND rg.source_id=$1 AND rg.generation_id=$2`,
		`DELETE FROM fi.source_batch sb USING fi.recorded_generation rg
          WHERE sb.recorded_generation_id=rg.recorded_generation_id AND rg.source_id=$1 AND rg.generation_id=$2`,
		`DELETE FROM fi.recorded_generation WHERE source_id=$1 AND generation_id=$2`,
	} {
		if _, err := tx.Exec(ctx, q, indexABSource, generationID); err != nil {
			t.Errorf("fixture lineage cleanup: %v", err)
			return
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM fi.ingest_journal
      WHERE source_id=$1 AND generation_id=$2 AND attempt_id=$3`, indexABSource, generationID, attemptID); err != nil {
		t.Errorf("fixture journal cleanup: %v", err)
		return
	}
	for _, q := range []string{
		`DELETE FROM fi.governed_root WHERE source_id=$1`,
		`DELETE FROM fi.ntfs_object WHERE ntfs_volume_id IN
          (SELECT ntfs_volume_id FROM fi.ntfs_volume WHERE source_id=$1)`,
		`DELETE FROM fi.ntfs_volume WHERE source_id=$1`,
	} {
		if _, err := tx.Exec(ctx, q, indexABSource); err != nil {
			t.Errorf("fixture NTFS cleanup: %v", err)
			return
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Errorf("fixture cleanup commit: %v", err)
		return
	}
	var gens, volumes, journals int64
	err = admin.QueryRow(ctx, `SELECT
      (SELECT count(*) FROM fi.recorded_generation WHERE source_id=$1),
      (SELECT count(*) FROM fi.ntfs_volume WHERE source_id=$1),
      (SELECT count(*) FROM fi.ingest_journal WHERE source_id=$1)`, indexABSource).
		Scan(&gens, &volumes, &journals)
	if err != nil || gens != 0 || volumes != 0 || journals != 0 {
		t.Errorf("fixture residual data gens=%d volumes=%d journals=%d err=%v", gens, volumes, journals, err)
	} else {
		t.Log("PASS: mixed signed fixture source-specific cleanup complete")
	}
}
