//go:build freebsd && fi_copy_latency_replay_integration

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, in the repository root.

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

const serialMixedSource = "fi-serial-mixed-ab.iss.local"

// TestSerialMixedGenerationReplay benchmarks a SINGLE authenticated generation
// through the real source-record and typed-relational ingest implementation.
// Every 4096 records contain 3584 contiguous Windows Security events
// with 15 child fields followed by 512 file observations. This 7:1 mix
// exercises large Security batching, file/hash batching and kind transitions.
//
// Only the existing, explicitly enabled M1 isolated FreeBSD/PostgreSQL 18
// fixture is writable. This test does NOT modify indexes or production data.
func TestSerialMixedGenerationReplay(t *testing.T) {
	if os.Getenv("FI_M1_ALLOW_ISOLATED_WRITES") != "1" {
		t.Skip("FI isolated writes explicitly disabled")
	}
	root := filepath.Join(os.Getenv("HOME"), "fi-m1-postgres-20261012")
	if os.Getenv("FI_M1_TEST_POSTGRES_ROOT") != root {
		t.Fatal("STOP: isolated PostgreSQL root approval mismatch")
	}
	version, err := os.ReadFile(filepath.Join(root, "data", "PG_VERSION"))
	if err != nil || string(version) != "18\n" {
		t.Fatal("STOP: isolated PostgreSQL 18 marker missing")
	}

	count := 8192
	if raw := os.Getenv("FI_SERIAL_MIXED_RECORDS"); raw != "" {
		count, err = strconv.Atoi(raw)
		if err != nil || count < 4096 || count > 16384 || count%4096 != 0 {
			t.Fatal("FI_SERIAL_MIXED_RECORDS must be 4096, 8192, 12288 or 16384")
		}
	}
	profile := os.Getenv("FI_SERIAL_MIXED_PROFILE")
	if profile == "" {
		profile = "P3"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	ctx, err = withFixedSecurityBulkProfile(ctx, profile)
	if err != nil {
		t.Fatal(err)
	}

	fileProfile := os.Getenv("FI_SERIAL_MIXED_FILE_PROFILE")
	if fileProfile == "" {
		fileProfile = "F1"
	}
	ctx, err = withFixedFileBulkProfile(ctx, fileProfile)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("FI SERIAL MIXED FILE PROFILE name=%s", fileProfile)

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

	ingest, state, err := OpenPostgreSQL(ctx, connect("fi_ingest"))
	if err != nil {
		t.Fatal(err)
	}
	defer ingest.Close(context.Background())
	m1VerifyIsolatedPostgreSQL(t, ctx, ingest, root, "fi_ingest")
	if state.RelationalTables != 49 {
		t.Fatalf("STOP: expected 49 relational tables; found %d", state.RelationalTables)
	}

	var generations, volumes, journal int64
	err = admin.QueryRow(ctx, `
SELECT
 (SELECT count(*) FROM fi.recorded_generation WHERE source_id=$1),
 (SELECT count(*) FROM fi.ntfs_volume WHERE source_id=$1),
 (SELECT count(*) FROM fi.ingest_journal WHERE source_id=$1)`,
		serialMixedSource).Scan(&generations, &volumes, &journal)
	if err != nil {
		t.Fatal(err)
	}
	if generations != 0 || volumes != 0 || journal != 0 {
		t.Fatalf("STOP: reserved fixture source is not empty: generations=%d volumes=%d journal=%d",
			generations, volumes, journal)
	}

	fixture := t.TempDir()
	for _, part := range []string{
		"custody", "recorded", "ready", filepath.Join("recorded", "sources", serialMixedSource),
	} {
		if err := os.MkdirAll(filepath.Join(fixture, part), 0700); err != nil {
			t.Fatal(err)
		}
	}

	now := time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z")
	input := make([]spool.Record, 0, count)
	fileNumber, securityNumber := 0, 0
	for i := 0; i < count; i++ {
		var kind, scope string
		var payload []byte
		if i%4096 >= 3584 {
			value, err := fileReplayObservation(fileNumber, now)
			if err != nil {
				t.Fatal(err)
			}
			payload, err = json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			kind, scope = "FileObservation", fileReplayScope
			fileNumber++
		} else {
			fields := make([]records.WindowsSecurityEventField, 0, securityReplayFields)
			for j := 0; j < securityReplayFields; j++ {
				fields = append(fields, records.WindowsSecurityEventField{
					Name: fmt.Sprintf("Field%02d", j), Value: fmt.Sprintf("value-%02d", j),
				})
			}
			event := records.WindowsSecurityEventObservation{
				ObservedAt:       now,
				CollectionMethod: records.WindowsSecurityCollectionMethod,
				Channel:          "Security",
				Provider:         "Microsoft-Windows-Security-Auditing",
				EventID:          "4663",
				EventRecordID:    strconv.Itoa(200000000 + securityNumber),
				TimeCreated:      now,
				Computer:         "fi-serial-mixed-replay.iss.local",
				AuditResult:      records.WindowsSecurityAuditSuccess,
				ScopeBasis:       records.WindowsSecurityScopePathMatched,
				MatchedScopes: []records.WindowsSecurityMatchedScope{{
					ScopeID: "security-replay", GovernedRoot: `C:\FI-Latency-Test`,
				}},
				Fields: fields,
				RawXML: fmt.Sprintf("<Event><RecordID>%d</RecordID></Event>", securityNumber),
			}
			if err := records.ValidateWindowsSecurityEventObservation(event); err != nil {
				t.Fatal(err)
			}
			payload, err = json.Marshal(event)
			if err != nil {
				t.Fatal(err)
			}
			kind, scope = "WindowsSecurityEvent", "security-replay"
			securityNumber++
		}
		input = append(input, spool.Record{
			Version: spool.RecordVersion, RecordKind: kind,
			ScopeID: scope, WrittenAt: now, Payload: payload,
		})
	}

	signed := m1WriteSignedGenerationRecords(t, fixture, serialMixedSource, input)
	attemptID := "serial-mixed-" + signed.GenerationID
	t.Cleanup(func() { cleanupSerialMixedReplay(t, admin, serialMixedSource, signed.GenerationID, attemptID) })

	config := GenerationLoadConfig{
		CustodyRoot:       filepath.Join(fixture, "custody"),
		RecordedRoot:      filepath.Join(fixture, "recorded"),
		SourceNamespaces:  true,
		SourceID:          serialMixedSource,
		MaxCanonicalBytes: 64 << 20,
		MaxEncodedBytes:   64 << 20,
		MaxManifestBytes:  1 << 20,
	}
	prepared, err := loadRecordedGenerationWithTrust(config, signed.GenerationID,
		func(source string) (generationTrustBundle, error) {
			if source != serialMixedSource {
				return generationTrustBundle{}, fmt.Errorf("unexpected source %q", source)
			}
			return signed.Trust, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	if prepared.Receipt.RecordCount != uint64(count) {
		t.Fatalf("signed receipt count %d, expected %d", prepared.Receipt.RecordCount, count)
	}
	if err := WriteAttemptStarted(ctx, ingest, attemptID, serialMixedSource, signed.GenerationID); err != nil {
		t.Fatal(err)
	}

	started := time.Now()
	result, err := IngestPreparedGeneration(ctx, ingest, attemptID, prepared)
	elapsed := time.Since(started)
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != "Accepted" || result.RecordsSeen != int64(count) || result.RecordsCommitted != int64(count) {
		t.Fatalf("unexpected mixed ingest outcome: %+v", result)
	}

	expected := map[string]int64{
		"source_record":                int64(count),
		"windows_security_event":       int64(securityNumber),
		"windows_security_event_field": int64(securityNumber * securityReplayFields),
		"windows_security_event_scope": int64(securityNumber),
		"file_observation":             int64(fileNumber),
		"file_metadata_observation":    int64(fileNumber),
		"content_hash_observation":     int64(fileNumber),
		"content_prefix_observation":   int64(fileNumber),
		"stream_observation":           int64(fileNumber),
		"security_observation":         int64(fileNumber),
		"sacl_observation":             int64(fileNumber),
	}
	for table, want := range expected {
		var got int64
		var q string
		if table == "source_record" {
			q = `SELECT count(*) FROM fi.source_record sr
JOIN fi.source_batch sb USING (source_batch_id)
JOIN fi.recorded_generation rg USING (recorded_generation_id)
WHERE rg.source_id=$1 AND rg.generation_id=$2`
		} else {
			q = fmt.Sprintf(`SELECT count(*) FROM fi.%s x
JOIN fi.source_record sr USING (source_record_id)
JOIN fi.source_batch sb USING (source_batch_id)
JOIN fi.recorded_generation rg USING (recorded_generation_id)
WHERE rg.source_id=$1 AND rg.generation_id=$2`, table)
		}
		err := admin.QueryRow(ctx, q, serialMixedSource, signed.GenerationID).Scan(&got)
		if err != nil || got != want {
			t.Fatalf("mixed relational verification table=%s got=%d want=%d err=%v", table, got, want, err)
		}
	}
	t.Logf("FI SERIAL MIXED ACCEPTED profile=%s source_records=%d security=%d file=%d fields=%d elapsed=%s rate=%.1f_records_per_second",
		profile, count, securityNumber, fileNumber, securityNumber*securityReplayFields,
		elapsed.Round(time.Millisecond), float64(count)/elapsed.Seconds())
}

// Only this reserved isolated source is eligible for cleanup. All cleanup
// tables are schema-defined constants, never user-supplied identifiers.
func cleanupSerialMixedReplay(t *testing.T, admin *pgx.Conn, source, generation, attemptID string) {
	t.Helper()
	if source != serialMixedSource {
		t.Error("STOP: refusing cleanup of an unrecognized source")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Errorf("begin isolated mixed cleanup: %v", err)
		return
	}
	defer tx.Rollback(context.Background())
	for _, table := range []string{
		"windows_security_event_field", "windows_security_event_scope", "windows_security_event",
		"stream_observation", "security_ace", "sacl_ace", "file_metadata_observation",
		"content_hash_observation", "content_prefix_observation", "reparse_observation",
		"stream_inventory", "security_observation", "sacl_observation",
		"observation_warning", "file_observation",
	} {
		q := fmt.Sprintf(`DELETE FROM fi.%s AS child
USING fi.source_record sr, fi.source_batch sb, fi.recorded_generation rg
WHERE child.source_record_id=sr.source_record_id
  AND sr.source_batch_id=sb.source_batch_id
  AND sb.recorded_generation_id=rg.recorded_generation_id
  AND rg.source_id=$1 AND rg.generation_id=$2`, table)
		if _, err := tx.Exec(ctx, q, source, generation); err != nil {
			t.Errorf("mixed cleanup %s: %v", table, err)
			return
		}
	}
	for _, q := range []string{
		`DELETE FROM fi.source_record sr USING fi.source_batch sb, fi.recorded_generation rg
WHERE sr.source_batch_id=sb.source_batch_id AND sb.recorded_generation_id=rg.recorded_generation_id
  AND rg.source_id=$1 AND rg.generation_id=$2`,
		`DELETE FROM fi.source_batch sb USING fi.recorded_generation rg
WHERE sb.recorded_generation_id=rg.recorded_generation_id
  AND rg.source_id=$1 AND rg.generation_id=$2`,
		`DELETE FROM fi.recorded_generation WHERE source_id=$1 AND generation_id=$2`,
	} {
		if _, err := tx.Exec(ctx, q, source, generation); err != nil {
			t.Errorf("mixed generation cleanup: %v", err)
			return
		}
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM fi.ingest_journal WHERE source_id=$1 AND generation_id=$2 AND attempt_id=$3`,
		source, generation, attemptID); err != nil {
		t.Errorf("mixed journal cleanup: %v", err)
		return
	}
	// Transaction-scoped support for NTFS parent FK checks.
	if _, err := tx.Exec(ctx, `CREATE INDEX fi_serial_mixed_parent_cleanup_idx
	    ON fi.file_observation(parent_ntfs_object_id)
	    WHERE parent_ntfs_object_id IS NOT NULL`); err != nil {
		t.Errorf("create mixed cleanup index: %v", err)
		return
	}
	for _, q := range []string{
		`DELETE FROM fi.governed_root WHERE source_id=$1`,
		`DELETE FROM fi.ntfs_object WHERE ntfs_volume_id IN
 (SELECT ntfs_volume_id FROM fi.ntfs_volume WHERE source_id=$1)`,
		`DELETE FROM fi.ntfs_volume WHERE source_id=$1`,
	} {
		if _, err := tx.Exec(ctx, q, source); err != nil {
			t.Errorf("mixed identity cleanup: %v", err)
			return
		}
	}
	if _, err := tx.Exec(ctx, `DROP INDEX fi.fi_serial_mixed_parent_cleanup_idx`); err != nil {
		t.Errorf("drop mixed cleanup index: %v", err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		t.Errorf("commit isolated mixed cleanup: %v", err)
		return
	}
	var generations, volumes, journal int64
	err = admin.QueryRow(ctx, `SELECT
 (SELECT count(*) FROM fi.recorded_generation WHERE source_id=$1),
 (SELECT count(*) FROM fi.ntfs_volume WHERE source_id=$1),
 (SELECT count(*) FROM fi.ingest_journal WHERE source_id=$1)`,
		source).Scan(&generations, &volumes, &journal)
	if err != nil || generations != 0 || volumes != 0 || journal != 0 {
		t.Errorf("mixed cleanup residual generations=%d volumes=%d journal=%d err=%v",
			generations, volumes, journal, err)
		return
	}
	t.Log("PASS: isolated mixed replay fixture fully cleaned")
}
