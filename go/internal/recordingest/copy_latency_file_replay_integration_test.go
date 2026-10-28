//go:build freebsd && fi_copy_latency_replay_integration

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
	"github.com/jackc/pgx/v5"
)

const (
	fileReplaySource  = "fi-file-replay.iss.local"
	fileReplayScope   = "fi-copy-file-replay"
	fileReplayDefault = 1024
	fileReplayMaximum = 4096
)

// TestCopyLatencyFileGenerationReplay uses the real signed-generation ingest
// path against ONLY the existing, verified isolated M1 PostgreSQL 18 fixture.
//
// All records represent synthetic 16-byte files with distinct MD5, SHA-1 and
// SHA-256 hashes. Each record projects one NTFS file, metadata observation,
// content-hash observation, content prefix and default stream. The test does
// not read Windows files, publish into the development SoR, or alter services.
//
// The explicit build tag, root path, port, cluster identity and write-approval
// gates are intentional. Never remove them to simplify running this benchmark.
func TestCopyLatencyFileGenerationReplay(t *testing.T) {
	if os.Getenv("FI_M1_ALLOW_ISOLATED_WRITES") != "1" {
		t.Skip("isolated PostgreSQL file replay not enabled")
	}

	root := filepath.Join(os.Getenv("HOME"), "fi-m1-postgres-20261012")
	if os.Getenv("FI_M1_TEST_POSTGRES_ROOT") != root {
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

// fileReplayObservation creates a valid NTFS file observation from synthetic
// source facts only; it does not access a Windows filesystem or use real data.
func fileReplayObservation(index int, observedAt string) (fileObservationPayload, error) {
	const rootPath = `C:\FI-Copy-Replay`
	const volumeGUID = `\\?\Volume{12345678-1234-1234-1234-123456789abc}\`

	volume := records.VolumeIdentity{
		MethodVersion: ntfs.IdentityMethodVersion,
		VolumeGUID:    volumeGUID,
		VolumeSerial:  "123456789",
	}
	rootObject := records.NTFSObjectIdentity{
		MethodVersion:       ntfs.IdentityMethodVersion,
		FileReferenceNumber: "5",
		SequenceNumber:      "1",
	}
	object := records.NTFSObjectIdentity{
		MethodVersion:       ntfs.IdentityMethodVersion,
		FileReferenceNumber: strconv.Itoa(1000 + index),
		SequenceNumber:      "1",
	}

	path := fmt.Sprintf(`%s\file-%06d.bin`, rootPath, index)
	pathEncoded := fileReplayUTF16Path(path)
	rootEncoded := fileReplayUTF16Path(rootPath)
	content := []byte(fmt.Sprintf("%016d", index))
	md5Digest := md5.Sum(content)
	sha1Digest := sha1.Sum(content)
	sha256Digest := sha256.Sum256(content)
	hashes := records.ContentHashObservation{
		State:       records.ContentHashPresent,
		BytesHashed: "16",
		MD5:         hex.EncodeToString(md5Digest[:]),
		SHA1:        hex.EncodeToString(sha1Digest[:]),
		SHA256:      hex.EncodeToString(sha256Digest[:]),
	}
	prefix := records.ContentPrefixObservation{
		State:           records.ContentPrefixPresent,
		BytesObserved:   "16",
		PrefixBase64URL: base64.RawURLEncoding.EncodeToString(content),
	}

	// Minimal valid self-relative security descriptors, no actual ACEs.
	// We intentionally isolate file/metadata/hash cost from ACE density.
	descriptor := make([]byte, 20)
	descriptor[0] = 1
	descriptor[3] = 0x80
	security, err := records.ParseSecurityDescriptor(descriptor)
	if err != nil {
		return fileObservationPayload{}, err
	}
	sacl, err := records.ParseSACLDescriptor(descriptor)
	if err != nil {
		return fileObservationPayload{}, err
	}

	defaultStream := records.StreamIdentityFromRawUTF16(utf16.Encode([]rune(`::$DATA`)))
	observation := ntfs.Observation{
		GovernedRoot: records.GovernedRootIdentity{
			ScopeID:                       fileReplayScope,
			RequestedPathUTF16LEBase64URL: rootEncoded,
			ResolvedPathUTF16LEBase64URL:  rootEncoded,
			MethodVersion:                 ntfs.ContainmentMethodVersion,
			VolumeIdentity:                volume,
			ObjectIdentity:                rootObject,
		},
		Containment:    records.PathContainment{MethodVersion: ntfs.ContainmentMethodVersion},
		VolumeIdentity: volume,
		ObjectIdentity: object,
		ParentBinding:  records.ParentObjectBindingFor(rootObject),
		SubjectKind:    records.SubjectFile,
		PathBinding: records.PathBinding{
			RequestedPathUTF16LEBase64URL: pathEncoded,
			ResolvedPathUTF16LEBase64URL:  pathEncoded,
		},
		ObservedAt: observedAt,
		Metadata: records.MetadataObservation{
			LogicalSize: "16", AllocatedSize: "4096",
			CreationTime: observedAt, LastWriteTime: observedAt,
			ChangeTime: observedAt, LastAccessTime: observedAt,
			RawAttributes: "32", LinkCount: "1",
		},
		Security: security,
		SACL:     sacl,
		Reparse: records.ReparseObservation{
			State:      records.ReparseStateNotPresent,
			DataState:  records.ReparseDataStateNotApplicable,
			DataFormat: records.ReparseDataFormatNotApplicable,
		},
		StreamInventory: records.StreamInventory{
			State: records.ObservationStatePresent,
			Streams: []records.StreamObservation{{
				Identity:    defaultStream,
				LogicalSize: "16", AllocatedSize: "4096",
			}},
		},
		ContentHashes:         &hashes,
		ContentPrefix:         &prefix,
		CollectionEntryMethod: ntfs.CollectionEntryPath,
		CollectionMethod:      records.CollectionDirectWindowsNTFS,
		ObservationStatus:     records.ObservationComplete,
	}
	return fileObservationPayload{NTFS: observation, ContentHashes: hashes}, nil
}

func fileReplayUTF16Path(path string) string {
	units := utf16.Encode([]rune(path))
	raw := make([]byte, len(units)*2)
	for i, unit := range units {
		binary.LittleEndian.PutUint16(raw[i*2:], unit)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// cleanupFileReplay deletes only the new generation's relational descendants.
// Test-source NTFS identities are removed after all file FK children. On any
// failure the transaction rolls back and the test fails closed.
func cleanupFileReplay(t *testing.T, admin *pgx.Conn, sourceID, generationID, attemptID string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Errorf("begin isolated file cleanup: %v", err)
		return
	}
	defer tx.Rollback(context.Background())

	for _, table := range []string{
		"stream_observation", "security_ace", "sacl_ace",
		"file_metadata_observation", "content_hash_observation",
		"content_prefix_observation", "reparse_observation",
		"stream_inventory", "security_observation", "sacl_observation",
		"observation_warning", "file_observation",
	} {
		query := fmt.Sprintf(`
DELETE FROM fi.%s AS child
USING fi.source_record sr, fi.source_batch sb, fi.recorded_generation rg
WHERE child.source_record_id=sr.source_record_id
  AND sr.source_batch_id=sb.source_batch_id
  AND sb.recorded_generation_id=rg.recorded_generation_id
  AND rg.source_id=$1 AND rg.generation_id=$2`, table)
		if _, err := tx.Exec(ctx, query, sourceID, generationID); err != nil {
			t.Errorf("clean up %s: %v", table, err)
			return
		}
	}
	// Remove the generation hierarchy, then its journal events.
	for _, query := range []string{
		`DELETE FROM fi.source_record sr USING fi.source_batch sb, fi.recorded_generation rg
		  WHERE sr.source_batch_id=sb.source_batch_id
		    AND sb.recorded_generation_id=rg.recorded_generation_id
		    AND rg.source_id=$1 AND rg.generation_id=$2`,
		`DELETE FROM fi.source_batch sb USING fi.recorded_generation rg
		  WHERE sb.recorded_generation_id=rg.recorded_generation_id
		    AND rg.source_id=$1 AND rg.generation_id=$2`,
		`DELETE FROM fi.recorded_generation WHERE source_id=$1 AND generation_id=$2`,
	} {
		if _, err := tx.Exec(ctx, query, sourceID, generationID); err != nil {
			t.Errorf("clean up isolated generation: %v", err)
			return
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM fi.ingest_journal
	    WHERE attempt_id=$1 AND source_id=$2 AND generation_id=$3`,
		attemptID, sourceID, generationID); err != nil {
		t.Errorf("clean up isolated ingest journal: %v", err)
		return
	}
	// Identity rows belong exclusively to this reserved synthetic source.
	for _, query := range []string{
		`DELETE FROM fi.governed_root WHERE source_id=$1`,
		`DELETE FROM fi.ntfs_object
		  WHERE ntfs_volume_id IN
		    (SELECT ntfs_volume_id FROM fi.ntfs_volume WHERE source_id=$1)`,
		`DELETE FROM fi.ntfs_volume WHERE source_id=$1`,
	} {
		if _, err := tx.Exec(ctx, query, sourceID); err != nil {
			t.Errorf("clean up isolated NTFS identities: %v", err)
			return
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Errorf("commit isolated file fixture cleanup: %v", err)
		return
	}

	var generations, volumes, journal int64
	err = admin.QueryRow(ctx, `
SELECT
    (SELECT count(*) FROM fi.recorded_generation WHERE source_id=$1),
    (SELECT count(*) FROM fi.ntfs_volume WHERE source_id=$1),
    (SELECT count(*) FROM fi.ingest_journal WHERE source_id=$1)`,
		sourceID).Scan(&generations, &volumes, &journal)
	if err != nil || generations != 0 || volumes != 0 || journal != 0 {
		t.Errorf("file fixture cleanup verification generations=%d volumes=%d journal=%d err=%v",
			generations, volumes, journal, err)
		return
	}
	t.Log("PASS: isolated file replay fixture rows cleaned")
}
