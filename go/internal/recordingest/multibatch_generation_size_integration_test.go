//go:build freebsd && fi_copy_latency_replay_integration

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, in the repository root.

package recordingest

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/generationrecorder"
	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportgeneration"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportreceiver"
	"github.com/jackc/pgx/v5"
)

const (
	multiBatchSource              = "fi-multibatch-size.iss.local"
	multiBatchDefaultBatchRecords = 8192
	// These are TEST-ONLY receiver/loader ceilings, not deployed defaults.
	// The real sender/receiver configuration must be evaluated separately.
	multiBatchMaxGenerationBytes uint64 = 512 << 20
)

// TestMultiBatchGenerationSizeReplay uses the production spool writer, signed
// generation sealer, transport receiver, recorder, and relational ingester.
// The sole writable database is the explicitly approved isolated M1 fixture.
// This is one atomic generation containing multiple real collector batches.
// It is NOT a test of multiple independently committed generations.
func TestMultiBatchGenerationSizeReplay(t *testing.T) {
	if os.Getenv("FI_M1_ALLOW_ISOLATED_WRITES") != "1" {
		t.Skip("isolated multi-batch PostgreSQL replay not enabled")
	}
	root := filepath.Join(os.Getenv("HOME"), "fi-m1-postgres-20261012")
	if os.Getenv("FI_M1_TEST_POSTGRES_ROOT") != root {
		t.Fatal("STOP: M1 isolated database root approval mismatch")
	}
	pgVersion, err := os.ReadFile(filepath.Join(root, "data", "PG_VERSION"))
	if err != nil || string(pgVersion) != "18\n" {
		t.Fatal("STOP: expected isolated PostgreSQL 18 fixture")
	}

	count := 32768
	if raw := os.Getenv("FI_MULTIBATCH_RECORDS"); raw != "" {
		count, err = strconv.Atoi(raw)
		if err != nil || (count != 32768 && count != 65536 && count != 98304 && count != 131072) {
			t.Fatal("FI_MULTIBATCH_RECORDS must be 32768, 65536, 98304, or 131072")
		}
	}
	mix := os.Getenv("FI_MULTIBATCH_MIX")
	if mix == "" {
		mix = "observed"
	}
	switch mix {
	case "file", "security", "balanced", "observed":
	default:
		t.Fatalf("unknown mix %q: expected file, security, balanced, or observed", mix)
	}
	batchRecords := multiBatchDefaultBatchRecords
	if raw := os.Getenv("FI_MULTIBATCH_BATCH_RECORDS"); raw != "" {
		batchRecords, err = strconv.Atoi(raw)
		if err != nil || (batchRecords != 4096 && batchRecords != 8192 && batchRecords != 16384) {
			t.Fatal("FI_MULTIBATCH_BATCH_RECORDS must be 4096, 8192, or 16384")
		}
	}
	fileProfile := os.Getenv("FI_MULTIBATCH_FILE_PROFILE")
	if fileProfile == "" {
		fileProfile = "F3"
	}
	securityProfile := os.Getenv("FI_MULTIBATCH_SECURITY_PROFILE")
	if securityProfile == "" {
		securityProfile = "P3"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	ctx, err = withFixedFileBulkProfile(ctx, fileProfile)
	if err != nil {
		t.Fatal(err)
	}
	ctx, err = withFixedSecurityBulkProfile(ctx, securityProfile)
	if err != nil {
		t.Fatal(err)
	}

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
		t.Fatalf("STOP: expected 49 FI relational tables, found %d", state.RelationalTables)
	}
	var generations, journal, volumes int64
	err = admin.QueryRow(ctx, `SELECT
      (SELECT count(*) FROM fi.recorded_generation WHERE source_id=$1),
      (SELECT count(*) FROM fi.ingest_journal WHERE source_id=$1),
      (SELECT count(*) FROM fi.ntfs_volume WHERE source_id=$1)`, multiBatchSource).
		Scan(&generations, &journal, &volumes)
	if err != nil || generations != 0 || journal != 0 || volumes != 0 {
		t.Fatalf("STOP: reserved multi-batch source not clean: generations=%d journal=%d volumes=%d err=%v",
			generations, journal, volumes, err)
	}

	fixture := t.TempDir()
	for _, part := range []string{"custody", "recorded", "ready",
		filepath.Join("recorded", "sources", multiBatchSource),
		filepath.Join(multiBatchSource, "frozen"),
		filepath.Join(multiBatchSource, "sealed")} {
		if err := os.MkdirAll(filepath.Join(fixture, part), 0700); err != nil {
			t.Fatal(err)
		}
	}

	builtAt := time.Now()
	signed, batchCount, sourceBytes, securityCount, fileCount :=
		writeMultiBatchSignedGeneration(t, fixture, mix, count, batchRecords)
	t.Logf("FI MULTIBATCH BUILT mix=%s records=%d source_batch_target_records=%d batches=%d source_bytes=%d security=%d file=%d elapsed=%s",
		mix, count, batchRecords, batchCount, sourceBytes, securityCount, fileCount, time.Since(builtAt).Round(time.Millisecond))
	if batchCount < 2 {
		t.Fatal("STOP: fixture did not produce multiple source batches")
	}

	attemptID := "multibatch-" + signed.GenerationID
	t.Cleanup(func() {
		cleanupMultiBatchReplay(t, admin, signed.GenerationID, attemptID)
	})
	loadConfig := GenerationLoadConfig{
		CustodyRoot:       filepath.Join(fixture, "custody"),
		RecordedRoot:      filepath.Join(fixture, "recorded"),
		SourceNamespaces:  true,
		SourceID:          multiBatchSource,
		MaxCanonicalBytes: multiBatchMaxGenerationBytes,
		MaxEncodedBytes:   multiBatchMaxGenerationBytes,
		MaxManifestBytes:  1 << 20,
	}
	prepared, err := loadRecordedGenerationWithTrust(loadConfig, signed.GenerationID,
		func(source string) (generationTrustBundle, error) {
			if source != multiBatchSource {
				return generationTrustBundle{}, fmt.Errorf("unexpected trust source %q", source)
			}
			return signed.Trust, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	if len(prepared.Batches) != batchCount ||
		prepared.Receipt.BatchCount != uint64(batchCount) ||
		prepared.Receipt.RecordCount != uint64(count) {
		t.Fatalf("STOP: signed receipt batch/record mismatch batches=%d/%d records=%d/%d",
			len(prepared.Batches), batchCount, prepared.Receipt.RecordCount, count)
	}
	// Enforce the exact source batch total independently of the receipt.
	var manifestRecords int
	for _, batch := range prepared.Batches {
		if batch.Manifest.RecordCount < 1 || batch.Manifest.RecordCount > batchRecords {
			t.Fatalf("invalid source batch %s: %d records", batch.BatchID, batch.Manifest.RecordCount)
		}
		manifestRecords += batch.Manifest.RecordCount
	}
	if manifestRecords != count {
		t.Fatalf("source batch manifest sum %d != %d", manifestRecords, count)
	}

	var walBefore string
	if err := admin.QueryRow(ctx, `SELECT pg_current_wal_lsn()::text`).Scan(&walBefore); err != nil {
		t.Fatal(err)
	}
	if err := WriteAttemptStarted(ctx, ingest, attemptID, multiBatchSource, signed.GenerationID); err != nil {
		t.Fatal(err)
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	started := time.Now()
	result, err := IngestPreparedGeneration(ctx, ingest, attemptID, prepared)
	elapsed := time.Since(started)
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != "Accepted" || result.RecordsSeen != int64(count) || result.RecordsCommitted != int64(count) {
		t.Fatalf("unexpected multi-batch ingest result: %+v", result)
	}

	// Compare every authoritative source record and major typed child table.
	expected := map[string]int64{
		"source_record":                int64(count),
		"windows_security_event":       int64(securityCount),
		"windows_security_event_field": int64(securityCount * securityReplayFields),
		"windows_security_event_scope": int64(securityCount),
		"file_observation":             int64(fileCount),
		"file_metadata_observation":    int64(fileCount),
		"content_hash_observation":     int64(fileCount),
		"content_prefix_observation":   int64(fileCount),
		"stream_observation":           int64(fileCount),
		"security_observation":         int64(fileCount),
		"sacl_observation":             int64(fileCount),
	}
	for table, want := range expected {
		query := fmt.Sprintf(`SELECT count(*) FROM fi.%s AS child
          JOIN fi.source_record sr USING (source_record_id)
          JOIN fi.source_batch sb USING (source_batch_id)
          JOIN fi.recorded_generation rg USING (recorded_generation_id)
          WHERE rg.source_id=$1 AND rg.generation_id=$2`, table)
		var got int64
		if err := admin.QueryRow(ctx, query, multiBatchSource, signed.GenerationID).Scan(&got); err != nil {
			t.Fatalf("verification query %s: %v", table, err)
		}
		if got != want {
			t.Fatalf("typed row mismatch table=%s got=%d want=%d", table, got, want)
		}
	}
	var recordedBatches int
	err = admin.QueryRow(ctx, `SELECT count(*) FROM fi.source_batch sb
       JOIN fi.recorded_generation rg USING (recorded_generation_id)
       WHERE rg.source_id=$1 AND rg.generation_id=$2`, multiBatchSource, signed.GenerationID).
		Scan(&recordedBatches)
	if err != nil || recordedBatches != batchCount {
		t.Fatalf("relational source batch count %d want %d err=%v", recordedBatches, batchCount, err)
	}
	var walBytes int64
	if err := admin.QueryRow(ctx, `SELECT pg_wal_lsn_diff(pg_current_wal_lsn(), $1::pg_lsn)::bigint`, walBefore).
		Scan(&walBytes); err != nil {
		t.Fatal(err)
	}
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		t.Fatal(err)
	}
	t.Logf("FI MULTIBATCH ACCEPTED mix=%s records=%d source_batch_target_records=%d batches=%d security=%d file=%d fields=%d file_profile=%s security_profile=%s ingest=%s throughput=%.1f_source_records_per_second wal_bytes=%d heap_before_mib=%.1f heap_after_mib=%.1f go_maxrss_kib=%d",
		mix, count, batchRecords, batchCount, securityCount, fileCount, securityCount*securityReplayFields,
		fileProfile, securityProfile, elapsed.Round(time.Millisecond), float64(count)/elapsed.Seconds(),
		walBytes, float64(before.HeapAlloc)/(1<<20), float64(after.HeapAlloc)/(1<<20), usage.Maxrss)
}

// These four profiles isolate source composition; no USN record is synthesized
// yet. "file" means NTFS FileObservation-heavy, not a full NTFS+USN workload.
func multiBatchIsSecurity(mix string, ordinal int) bool {
	switch mix {
	case "file":
		return false
	case "security":
		return true
	case "balanced":
		return ordinal%4096 < 2048
	default:
		return ordinal%4096 < 3584 // observed 7/8 security
	}
}

func writeMultiBatchSignedGeneration(t *testing.T, fixture, mix string, count, batchRecords int) (m1SignedSource, int, int64, int, int) {
	t.Helper()
	trust, signer, certificate := m1MakeSignedTrust(t, multiBatchSource)
	sourceDir := filepath.Join(fixture, multiBatchSource)
	frozen := filepath.Join(sourceDir, "frozen")
	sealed := filepath.Join(sourceDir, "sealed")
	writer, err := spool.NewWriter(frozen, batchRecords, spool.CollectorIdentity{
		ExecutablePath: `C:\Program Files\FI\fi.exe`,
		ExecutableSHA256: "1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a" +
			"1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a",
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z")
	fileCount, securityCount := 0, 0
	for i := 0; i < count; i++ {
		if multiBatchIsSecurity(mix, i) {
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
				EventRecordID:    strconv.Itoa(300000000 + securityCount),
				TimeCreated:      now,
				Computer:         multiBatchSource,
				AuditResult:      records.WindowsSecurityAuditSuccess,
				ScopeBasis:       records.WindowsSecurityScopePathMatched,
				MatchedScopes: []records.WindowsSecurityMatchedScope{{
					ScopeID: "security-replay", GovernedRoot: `C:\FI-Latency-Test`,
				}},
				Fields: fields,
				RawXML: fmt.Sprintf("<Event><RecordID>%d</RecordID></Event>", securityCount),
			}
			if err := records.ValidateWindowsSecurityEventObservation(event); err != nil {
				t.Fatal(err)
			}
			if err := writer.Append("WindowsSecurityEvent", "security-replay", event); err != nil {
				t.Fatalf("spool security record %d: %v", i, err)
			}
			securityCount++
		} else {
			file, err := fileReplayObservation(fileCount, now)
			if err != nil {
				t.Fatal(err)
			}
			if err := writer.Append("FileObservation", fileReplayScope, file); err != nil {
				t.Fatalf("spool file record %d: %v", i, err)
			}
			fileCount++
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	batches := writer.FinalizedBatches()
	var sourceBytes int64
	var sum int
	for _, batch := range batches {
		if batch.Manifest.RecordCount > batchRecords || batch.Manifest.DataBytes > spool.DefaultTargetBatchBytes {
			t.Fatalf("bad batch bounds count=%d bytes=%d", batch.Manifest.RecordCount, batch.Manifest.DataBytes)
		}
		sum += batch.Manifest.RecordCount
		sourceBytes += batch.Manifest.DataBytes
	}
	if sum != count || len(batches) < 2 {
		t.Fatalf("source batch construction mismatch: sum=%d want=%d batches=%d", sum, count, len(batches))
	}

	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	generationID := time.Now().UTC().Format("20060102T150405.000000000Z") + "-" + hex.EncodeToString(nonce)
	published, err := transportgeneration.CreateSealedGeneration(context.Background(), transportgeneration.CreateConfig{
		BatchSigner:             signer,
		BatchSigningCertificate: certificate,
		FrozenDir:               frozen,
		GenerationID:            generationID,
		SealedRoot:              sealed,
		SourceID:                multiBatchSource,
		MaxEncodedBytes:         multiBatchMaxGenerationBytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	offer, err := transportgeneration.OfferFromPublished(published)
	if err != nil {
		t.Fatal(err)
	}

	// The old M1 helper used a bytes.Buffer for the entire wire generation.
	// Write to a file to avoid duplicating hundreds of MiB in Go heap.
	wire, err := os.CreateTemp(fixture, "fi-multibatch-wire-*.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer wire.Close()
	if err := wire.Chmod(0600); err != nil {
		t.Fatal(err)
	}
	if err := transportgeneration.WriteOffer(wire, offer); err != nil {
		t.Fatal(err)
	}
	if _, err := transportgeneration.WritePublishedGeneration(wire, published); err != nil {
		t.Fatal(err)
	}
	if _, err := wire.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	receiver := transportreceiver.GenerationReceiveConfig{
		Custody: transportgeneration.CustodyConfig{
			RootDir: filepath.Join(fixture, "custody"),
			Receive: transportgeneration.ReceiveConfig{
				BatchCRL: trust.BatchCRL, BatchIssuer: trust.BatchIssuer,
				CurrentTime:       time.Now().UTC(),
				MaxCanonicalBytes: multiBatchMaxGenerationBytes,
				MaxEncodedBytes:   multiBatchMaxGenerationBytes,
				Root:              trust.Root, Source: trust.Source,
			},
		},
		ReadyRoot: filepath.Join(fixture, "ready"),
		Recorder: generationrecorder.DurableConfig{
			RootDir:          filepath.Join(fixture, "recorded"),
			SourceNamespaces: true,
			Semantic:         generationrecorder.Config{MaxManifestBytes: 1 << 20},
		},
	}
	var output bytes.Buffer
	receiveResult, err := transportreceiver.ReceiveGenerationAndAcknowledge(wire, &output, receiver)
	if err != nil {
		t.Fatal(err)
	}
	if receiveResult.Recorder.Disposition != generationrecorder.RecordedDispositionNew || receiveResult.ReadyWarning != "" {
		t.Fatalf("receiver disposition=%q ready_warning=%q", receiveResult.Recorder.Disposition, receiveResult.ReadyWarning)
	}
	decision, err := transportgeneration.ReadDecision(&output)
	if err != nil {
		t.Fatal(err)
	}
	ack, err := transportgeneration.ReadAcknowledgement(&output)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Accepted || ack.Outcome != transportgeneration.AcknowledgementOutcomeRecorded {
		t.Fatalf("signed generation not acknowledged: decision=%+v ack=%+v", decision, ack)
	}
	return m1SignedSource{
		GenerationID: generationID, SourceID: multiBatchSource,
		ReceiptPath: receiveResult.Recorder.ReceiptPath, Trust: trust,
	}, len(batches), sourceBytes, securityCount, fileCount
}

func cleanupMultiBatchReplay(t *testing.T, admin *pgx.Conn, generation, attemptID string) {
	t.Helper()
	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	// Fail closed if an unrelated fixture or permanent schema change exists.
	if multiBatchSource != "fi-multibatch-size.iss.local" {
		t.Fatal("STOP: unexpected fixture source")
	}
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Errorf("begin multi-batch cleanup: %v", err)
		return
	}
	defer tx.Rollback(context.Background())
	for _, table := range []string{
		"windows_security_event_field", "windows_security_event_scope", "windows_security_event",
		"stream_observation", "security_ace", "sacl_ace",
		"file_metadata_observation", "content_hash_observation",
		"content_prefix_observation", "reparse_observation",
		"stream_inventory", "security_observation", "sacl_observation",
		"observation_warning", "file_observation",
	} {
		query := fmt.Sprintf(`DELETE FROM fi.%s AS child
          USING fi.source_record sr, fi.source_batch sb, fi.recorded_generation rg
          WHERE child.source_record_id=sr.source_record_id
            AND sr.source_batch_id=sb.source_batch_id
            AND sb.recorded_generation_id=rg.recorded_generation_id
            AND rg.source_id=$1 AND rg.generation_id=$2`, table)
		if _, err := tx.Exec(ctx, query, multiBatchSource, generation); err != nil {
			t.Errorf("cleanup table %s: %v", table, err)
			return
		}
	}
	for _, query := range []string{
		`DELETE FROM fi.source_record sr USING fi.source_batch sb, fi.recorded_generation rg
           WHERE sr.source_batch_id=sb.source_batch_id AND sb.recorded_generation_id=rg.recorded_generation_id
             AND rg.source_id=$1 AND rg.generation_id=$2`,
		`DELETE FROM fi.source_batch sb USING fi.recorded_generation rg
           WHERE sb.recorded_generation_id=rg.recorded_generation_id AND rg.source_id=$1 AND rg.generation_id=$2`,
		`DELETE FROM fi.recorded_generation WHERE source_id=$1 AND generation_id=$2`,
	} {
		if _, err := tx.Exec(ctx, query, multiBatchSource, generation); err != nil {
			t.Errorf("cleanup generation hierarchy: %v", err)
			return
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM fi.ingest_journal
        WHERE attempt_id=$1 AND source_id=$2 AND generation_id=$3`, attemptID, multiBatchSource, generation); err != nil {
		t.Errorf("cleanup ingest journal: %v", err)
		return
	}
	// FK probes for each NTFS identity otherwise repeatedly scan other
	// test sources' file_observation.parent_ntfs_object_id rows.
	if _, err := tx.Exec(ctx, `CREATE INDEX fi_multibatch_parent_cleanup_idx
        ON fi.file_observation(parent_ntfs_object_id)
        WHERE parent_ntfs_object_id IS NOT NULL`); err != nil {
		t.Errorf("create isolated multi-batch cleanup index: %v", err)
		return
	}
	for _, query := range []string{
		`DELETE FROM fi.governed_root WHERE source_id=$1`,
		`DELETE FROM fi.ntfs_object WHERE ntfs_volume_id IN
          (SELECT ntfs_volume_id FROM fi.ntfs_volume WHERE source_id=$1)`,
		`DELETE FROM fi.ntfs_volume WHERE source_id=$1`,
	} {
		if _, err := tx.Exec(ctx, query, multiBatchSource); err != nil {
			t.Errorf("cleanup NTFS identities: %v", err)
			return
		}
	}
	if _, err := tx.Exec(ctx, `DROP INDEX fi.fi_multibatch_parent_cleanup_idx`); err != nil {
		t.Errorf("drop isolated multi-batch cleanup index: %v", err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		t.Errorf("commit multi-batch cleanup: %v", err)
		return
	}
	var generations, journal, volumes int64
	var indexExists bool
	err = admin.QueryRow(ctx, `SELECT
      (SELECT count(*) FROM fi.recorded_generation WHERE source_id=$1),
      (SELECT count(*) FROM fi.ingest_journal WHERE source_id=$1),
      (SELECT count(*) FROM fi.ntfs_volume WHERE source_id=$1),
      to_regclass('fi.fi_multibatch_parent_cleanup_idx') IS NOT NULL`, multiBatchSource).
		Scan(&generations, &journal, &volumes, &indexExists)
	if err != nil || generations != 0 || journal != 0 || volumes != 0 || indexExists {
		t.Errorf("multi-batch cleanup verification: gen=%d journal=%d volumes=%d index=%t err=%v",
			generations, journal, volumes, indexExists, err)
		return
	}
	t.Logf("PASS: isolated multi-batch replay fully cleaned elapsed=%s", time.Since(started).Round(time.Millisecond))
}