//go:build freebsd && fi_copy_latency_replay_integration && fi_hash_signed_gate_integration

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Local isolated PostgreSQL signed-generation acceptance for hash-index
// comparison. This file is generated from FI's existing signed replay test
// without changing the authoritative test or production implementation.

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

	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
	"github.com/jackc/pgx/v5"
)

// TestHashSignedIndexGenerationReplay exercises immutable signed custody,
// receipt validation, all ordinary FI file/metadata/children/hash projections,
// durable generation acceptance, and isolated cleanup. Run once with each
// candidate index layout. Each run is exactly one full-generation transaction.

func TestHashSignedIndexGenerationReplay(t *testing.T) {
	if os.Getenv("FI_HASH_SIGNED_ALLOW_ISOLATED_WRITES") != "1" {
		t.Skip("isolated PostgreSQL file replay not enabled")
	}

	root := "/home/jwood/fi-prefetch-20261030.CTwtoA"
	if os.Getenv("FI_HASH_SIGNED_TEST_POSTGRES_ROOT") != root {
		t.Fatal("STOP: unexpected isolated PostgreSQL root")
	}
	version, err := os.ReadFile(filepath.Join(root, "data", "PG_VERSION"))
	if err != nil || string(version) != "18\n" {
		t.Fatal("STOP: isolated PostgreSQL 18 marker missing")
	}

	count := fileReplayDefault
	if value := os.Getenv("FI_COPY_LATENCY_FILE_RECORDS"); value != "" {
		count, err = strconv.Atoi(value)
		if err != nil || count < 1 || count > fileReplayMaximum {
			t.Fatal("FI_COPY_LATENCY_FILE_RECORDS must be 1..4096")
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	connect := func(user string) string {
		return fmt.Sprintf(
			"host=%s port=55442 user=%s dbname=fi sslmode=disable connect_timeout=3",
			filepath.Join(root, "socket"), user,
		)
	}

	admin, err := pgx.Connect(ctx, connect("jwood"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close(context.Background()) })
	hashSignedVerifyIsolatedPostgreSQL(t, ctx, admin, root, "jwood")

	runtime, state, err := OpenPostgreSQL(ctx, connect("fi_ingest"))
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close(context.Background())
	hashSignedVerifyIsolatedPostgreSQL(t, ctx, runtime, root, "fi_ingest")
	if state.RelationalTables != 49 {
		t.Fatalf("STOP: isolated fixture has %d relational tables, expected 49", state.RelationalTables)
	}

	// Refuse to reuse the test source if a previous failed run left rows.
	// Cleanup is restricted to rows this exact replay source created.
	var previousGenerations, previousVolumes, previousJournal int64
	err = admin.QueryRow(ctx, `
SELECT
    (SELECT count(*) FROM fi.recorded_generation WHERE source_id=$1),
    (SELECT count(*) FROM fi.ntfs_volume WHERE source_id=$1),
    (SELECT count(*) FROM fi.ingest_journal WHERE source_id=$1)`,
		fileReplaySource).Scan(&previousGenerations, &previousVolumes, &previousJournal)
	if err != nil {
		t.Fatal(err)
	}
	if previousGenerations != 0 || previousVolumes != 0 || previousJournal != 0 {
		t.Fatalf("STOP: preexisting replay fixture state generations=%d volumes=%d journal=%d",
			previousGenerations, previousVolumes, previousJournal)
	}

	fixtureRoot := t.TempDir()
	for _, part := range []string{
		"custody", "recorded", "ready",
		filepath.Join("recorded", "sources", fileReplaySource),
	} {
		if err := os.MkdirAll(filepath.Join(fixtureRoot, part), 0700); err != nil {
			t.Fatal(err)
		}
	}

	// Validate the record facts before signing; keep all generated content
	// deterministic for the same record index, except observation timestamps.
	input := make([]spool.Record, 0, count)
	now := time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z")
	for i := 0; i < count; i++ {
		value, err := fileReplayObservation(i, now)
		if err != nil {
			t.Fatalf("create file observation %d: %v", i, err)
		}
		if err := ntfs.ValidateObservation(value.NTFS); err != nil {
			t.Fatalf("invalid NTFS observation %d: %v", i, err)
		}
		payload, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		input = append(input, spool.Record{
			Version:    spool.RecordVersion,
			RecordKind: "FileObservation",
			ScopeID:    fileReplayScope,
			WrittenAt:  now,
			Payload:    payload,
		})
	}

	signed := m1WriteSignedGenerationRecords(t, fixtureRoot, fileReplaySource, input)
	attemptID := "copy-latency-file-" + signed.GenerationID
	t.Cleanup(func() {
		cleanupFileReplay(t, admin, fileReplaySource, signed.GenerationID, attemptID)
	})

	config := GenerationLoadConfig{
		CustodyRoot:       filepath.Join(fixtureRoot, "custody"),
		RecordedRoot:      filepath.Join(fixtureRoot, "recorded"),
		SourceNamespaces:  true,
		SourceID:          fileReplaySource,
		MaxCanonicalBytes: 64 << 20,
		MaxEncodedBytes:   64 << 20,
		MaxManifestBytes:  1 << 20,
	}
	prepared, err := loadRecordedGenerationWithTrust(config, signed.GenerationID,
		func(source string) (generationTrustBundle, error) {
			if source != fileReplaySource {
				return generationTrustBundle{}, fmt.Errorf("unexpected test source %q", source)
			}
			return signed.Trust, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	if prepared.Receipt.RecordCount != uint64(count) || len(prepared.Batches) != 1 {
		t.Fatal("signed replay receipt does not match generated file count")
	}

	if err := WriteAttemptStarted(ctx, runtime, attemptID, fileReplaySource, signed.GenerationID); err != nil {
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
		t.Fatalf("unexpected file replay outcome: %+v", result)
	}

	// Every source record must have exactly one row in each expected table.
	var files, metadata, hashes, prefixes, streams, security, sacl int64
	err = admin.QueryRow(ctx, `
SELECT
    count(*),
    count(m.source_record_id),
    count(h.source_record_id),
    count(p.source_record_id),
    count(s.source_record_id),
    count(sec.source_record_id),
    count(sa.source_record_id)
FROM fi.file_observation f
JOIN fi.source_record sr USING (source_record_id)
JOIN fi.source_batch sb USING (source_batch_id)
JOIN fi.recorded_generation rg USING (recorded_generation_id)
LEFT JOIN fi.file_metadata_observation m USING (source_record_id)
LEFT JOIN fi.content_hash_observation h USING (source_record_id)
LEFT JOIN fi.content_prefix_observation p USING (source_record_id)
LEFT JOIN fi.stream_observation s USING (source_record_id)
LEFT JOIN fi.security_observation sec USING (source_record_id)
LEFT JOIN fi.sacl_observation sa USING (source_record_id)
WHERE rg.source_id=$1 AND rg.generation_id=$2`,
		fileReplaySource, signed.GenerationID).
		Scan(&files, &metadata, &hashes, &prefixes, &streams, &security, &sacl)
	if err != nil {
		t.Fatal(err)
	}
	want := int64(count)
	if files != want || metadata != want || hashes != want ||
		prefixes != want || streams != want || security != want || sacl != want {
		t.Fatalf("file replay relational mismatch files=%d metadata=%d hashes=%d prefixes=%d streams=%d security=%d sacl=%d expected=%d",
			files, metadata, hashes, prefixes, streams, security, sacl, want)
	}
	t.Logf("FI FILE REPLAY ACCEPTED records=%d files=%d metadata=%d hashes=%d prefixes=%d streams=%d elapsed=%s rate=%.1f_records_per_second",
		count, files, metadata, hashes, prefixes, streams,
		elapsed.Round(time.Millisecond), float64(count)/elapsed.Seconds())
	t.Log("Observe INGEST COPY LATENCY FILE and INGEST PROFILE above for per-COPY latency and stage timings")
}

// Confirm the actual backend, not just the DSN. The read-only role cannot
// access data_directory, but its socket and database/user identity are checked.
func hashSignedVerifyIsolatedPostgreSQL(t *testing.T, ctx context.Context, c *pgx.Conn, root, role string) {
	t.Helper()
	socket := filepath.Join(root, "socket")
	cfg := c.Config()
	if cfg.Host != socket || cfg.Port != 55442 || cfg.Database != "fi" || cfg.User != role {
		t.Fatalf("STOP: unexpected isolated endpoint: host=%q port=%d db=%q user=%q", cfg.Host, cfg.Port, cfg.Database, cfg.User)
	}
	var listen, db, user, port string
	err := c.QueryRow(ctx, `SELECT current_setting('listen_addresses'),current_database(),current_user,current_setting('port')`).Scan(&listen, &db, &user, &port)
	if err != nil || listen != "" || db != "fi" || user != role || port != "55442" {
		t.Fatalf("STOP: isolated backend identity: listen=%q db=%q user=%q port=%q err=%v", listen, db, user, port, err)
	}
	if role == "jwood" {
		var actual string
		err = c.QueryRow(ctx, `SELECT current_setting('data_directory')`).Scan(&actual)
		if err != nil || actual != filepath.Join(root, "data") {
			t.Fatalf("STOP: unexpected isolated data_directory=%q err=%v", actual, err)
		}
	}
}
