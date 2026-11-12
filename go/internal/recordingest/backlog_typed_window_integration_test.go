//go:build freebsd && fi_backlog_typed_window_integration

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
	"github.com/jackc/pgx/v5"
)

//go:embed backlog_artifact_ledger_schema.sql
var isolatedTypedWindowSchema string

func privateTypedFixture(t *testing.T, source string, badLate bool) *PreparedGeneration {
	t.Helper()
	g := backlogWindowFixture([]int{3, 3}, 1)
	g.Receipt.Version = "fi-fixture-recorded-receipt/1"
	d := &g.Receipt.Descriptor
	d.Version = "fi-fixture-generation/1"
	d.SourceID = source
	d.GenerationID = "20261101T130000.000000000Z-typed-test"
	d.CanonicalVersion = "fi-test-canonical"
	d.DataEncoding = "fi-test-encoding"
	d.ArtifactCount = 4
	d.SourceBytes = 4096
	d.CanonicalBytes = 4096
	d.CanonicalSHA256 = strings.Repeat("1", 64)
	d.EncodedDataBytes = 2048
	d.EncodedDataSHA256 = strings.Repeat("2", 64)
	g.Receipt.MetadataBytes = 256
	g.Receipt.MetadataSHA256 = strings.Repeat("3", 64)
	g.Receipt.TransferBytes = 4096
	g.Receipt.TransferSHA256 = strings.Repeat("4", 64)
	g.ReceiptSHA256 = strings.Repeat("5", 64)
	if badLate {
		d.GenerationID = "20261101T130001.000000000Z-typed-bad"
		g.Receipt.TransferSHA256 = strings.Repeat("6", 64)
		g.ReceiptSHA256 = strings.Repeat("7", 64)
	}
	g.ReceiptBytes = 256
	g.Receipt.DataBytes = 0
	for bi := range g.Batches {
		b := &g.Batches[bi]
		b.DataArtifactName = "batch-" + b.BatchID + ".jsonl"
		b.ManifestArtifactName = "batch-" + b.BatchID + ".manifest.json"
		b.Manifest.DataFile = b.DataArtifactName
		b.Manifest.Version = "fi-fixture-spool-manifest"
		b.Manifest.CreatedAt = "2026-11-01T12:59:00Z"
		b.Manifest.CompletedAt = "2026-11-01T13:00:00Z"
		b.Manifest.Collector.ExecutablePath = "C:\\FI\\synthetic.exe"
		b.Manifest.Collector.ExecutableSHA256 = strings.Repeat("8", 64)
		var data []byte
		for n := 0; n < b.Manifest.RecordCount; n++ {
			kind := "NTFSCollectionError"
			var payload any = ntfsCollectionErrorPayload{
				PathDisplay:          "C:\\FI\\test",
				PathUTF16LEBase64URL: base64.RawURLEncoding.EncodeToString([]byte{'C', 0, ':', 0, '\\', 0, 'F', 0, 'I', 0}),
				Error:                "synthetic",
			}
			if bi == 1 {
				kind = "SupportingSourceCollectionError"
				payload = supportingSourceCollectionErrorPayload{Source: "synthetic", Error: "synthetic"}
			}
			if badLate && bi == 0 && n == 2 {
				payload = ntfsCollectionErrorPayload{PathDisplay: "C:\\bad", PathUTF16LEBase64URL: "invalid%%%", Error: "late projection failure"}
			}
			rawPayload, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			env := spool.Record{
				Version: SpoolRecordVersion, RecordKind: kind,
				ScopeID:   fmt.Sprintf("test-scope-%d", bi),
				WrittenAt: "2026-11-01T13:00:00.123456789Z", Payload: rawPayload,
			}
			recordBytes, err := json.Marshal(env)
			if err != nil {
				t.Fatal(err)
			}
			data = append(data, recordBytes...)
			data = append(data, '\n')
		}
		file := filepath.Join(t.TempDir(), "data.jsonl")
		if err := os.WriteFile(file, data, 0600); err != nil {
			t.Fatal(err)
		}
		b.DataPath = file
		b.Manifest.DataBytes = int64(len(data))
		hash := sha256.Sum256(data)
		b.Manifest.DataSHA256 = hex.EncodeToString(hash[:])
		manifestBytes, err := json.Marshal(b.Manifest)
		if err != nil {
			t.Fatal(err)
		}
		b.ManifestRawBytes = manifestBytes
		b.ManifestBytes = len(manifestBytes)
		mh := sha256.Sum256(manifestBytes)
		b.ManifestSHA256 = hex.EncodeToString(mh[:])
		g.Receipt.DataBytes += uint64(len(data))
	}
	return g
}

func TestBacklogTypedWindowIsolatedDurableAtomicity(t *testing.T) {
	if os.Getenv("FI_M1_ALLOW_ISOLATED_WRITES") != "1" {
		t.Skip("isolated PostgreSQL writes disabled")
	}
	root := filepath.Join(os.Getenv("HOME"), "fi-m1-postgres-20261012")
	if os.Getenv("FI_M1_TEST_POSTGRES_ROOT") != root {
		t.Fatal("STOP: unexpected PostgreSQL root")
	}
	pgversion, err := os.ReadFile(filepath.Join(root, "data", "PG_VERSION"))
	if err != nil || string(pgversion) != "18\n" {
		t.Fatal("STOP: PostgreSQL 18 root missing")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	connect := func(user string) string {
		return fmt.Sprintf(
			"host=%s port=55418 user=%s dbname=fi sslmode=disable connect_timeout=3",
			filepath.Join(root, "socket"), user)
	}
	admin, err := pgx.Connect(ctx, connect("fi_m1_admin"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close(context.Background()) })
	writer, err := pgx.Connect(ctx, connect("fi_ingest"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close(context.Background()) })
	reader, err := pgx.Connect(ctx, connect("fi_ingest"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close(context.Background()) })
	for _, p := range []struct {
		c    *pgx.Conn
		role string
	}{{admin, "fi_m1_admin"}, {writer, "fi_ingest"}, {reader, "fi_ingest"}} {
		var role, db, port, version string
		if err := p.c.QueryRow(ctx, `SELECT current_user,current_database(),
current_setting('port'),current_setting('server_version_num')`).Scan(&role, &db, &port, &version); err != nil {
			t.Fatal(err)
		}
		if role != p.role || db != "fi" || port != "55418" || !strings.HasPrefix(version, "18") {
			t.Fatal("STOP: isolated connection identity mismatch")
		}
	}
	var dir string
	if err := admin.QueryRow(ctx, "SELECT current_setting('data_directory')").Scan(&dir); err != nil {
		t.Fatal(err)
	}
	if filepath.Clean(dir) != filepath.Join(root, "data") {
		t.Fatal("STOP: PostgreSQL data directory mismatch")
	}
	var present bool
	if err := admin.QueryRow(ctx, `SELECT
(to_regnamespace('fi_recovery') IS NOT NULL OR
to_regnamespace('fi_recovery_projection') IS NOT NULL)`).Scan(&present); err != nil {
		t.Fatal(err)
	}
	if present {
		t.Fatal("STOP: existing FI recovery schema cannot be overwritten")
	}

	if _, err := admin.Exec(ctx, isolatedTypedWindowSchema, pgx.QueryExecModeSimpleProtocol); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, done := context.WithTimeout(context.Background(), 30*time.Second)
		defer done()
		if _, err := admin.Exec(c, "DROP SCHEMA fi_recovery CASCADE"); err != nil {
			t.Errorf("test-owned ledger cleanup: %v", err)
		}
	})
	for i, name := range []string{"0001_relational.sql", "0002_source_families.sql",
		"0003_usn_relational_identity.sql", "0004_security_field_name_index.sql",
		"0005_usn_capture_binding.sql"} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "..", "database", "schema", name))
		if err != nil {
			t.Fatal(err)
		}
		ddl, err := RewritePrivateProjectionMigration(name, string(raw))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := admin.Exec(ctx, ddl, pgx.QueryExecModeSimpleProtocol); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if i == 0 {
			t.Cleanup(func() {
				c, done := context.WithTimeout(context.Background(), 30*time.Second)
				defer done()
				if _, err := admin.Exec(c, "DROP SCHEMA fi_recovery_projection CASCADE"); err != nil {
					t.Errorf("shadow schema cleanup: %v", err)
				}
			})
		}
	}
	var canUpdate, canDelete bool
	if err := writer.QueryRow(ctx, `
SELECT has_table_privilege('fi_ingest','fi_recovery.typed_window','UPDATE'),
       has_table_privilege('fi_ingest','fi_recovery.typed_window','DELETE')
`).Scan(&canUpdate, &canDelete); err != nil {
		t.Fatal(err)
	}
	if canUpdate || canDelete {
		t.Fatal("STOP: runtime has destructive typed marker authority")
	}

	g := privateTypedFixture(t, "fi-typed-window-isolated.iss.local", false)
	privateRoot := privateBacklogTestRoot(t)
	limits := BacklogWindowLimits{MaxRecords: 3, MaxDataBytes: 1 << 20}
	for i := 0; i < 2; i++ {
		if _, err := MaterializeBacklogWindow(ctx, g, limits, i, privateRoot); err != nil {
			t.Fatal(err)
		}
		if err := RecordVerifiedBacklogArtifactWindow(ctx, writer, g, limits, i, privateRoot); err != nil {
			t.Fatal(err)
		}
		if err := StageVerifiedBacklogSourceWindow(ctx, writer, g, limits, i, privateRoot); err != nil {
			t.Fatal(err)
		}
	}
	if err := StageBacklogTypedWindow(ctx, reader, writer, g, limits, 1, privateRoot); err == nil {
		t.Fatal("window 1 accepted without completed typed window 0")
	}
	if err := StageBacklogTypedWindow(ctx, reader, writer, g, limits, 0, privateRoot); err != nil {
		t.Fatal(err)
	}
	// A private generation cannot be declared complete from its first
	// committed typed window, even when all existing projections are valid.
	if _, err := VerifyCompleteBacklogTypedGeneration(ctx, reader, g, limits); err == nil {
		t.Fatal("partial staged generation incorrectly verified as complete")
	}
	if err := writer.Close(ctx); err != nil {
		t.Fatal(err)
	}
	writer, err = pgx.Connect(ctx, connect("fi_ingest"))
	if err != nil {
		t.Fatal(err)
	}
	if err := StageBacklogTypedWindow(ctx, reader, writer, g, limits, 0, privateRoot); err != nil {
		t.Fatalf("committed typed window not resumable: %v", err)
	}
	if err := StageBacklogTypedWindow(ctx, reader, writer, g, limits, 1, privateRoot); err != nil {
		t.Fatal(err)
	}
	completed, err := VerifyCompleteBacklogTypedGeneration(ctx, reader, g, limits)
	if err != nil {
		t.Fatalf("whole-generation private verification failed: %v", err)
	}
	if completed.Windows != 2 || completed.Records != 6 ||
		completed.DataBytes != g.Receipt.DataBytes || completed.ReceiptSHA256 != g.ReceiptSHA256 ||
		completed.SourceID != g.Receipt.Descriptor.SourceID ||
		completed.GenerationID != g.Receipt.Descriptor.GenerationID ||
		completed.ShadowGenerationID <= 0 {
		t.Fatalf("wrong whole-generation verification result: %+v", completed)
	}
	// The source/typed identity comparison must detect an admin-side change
	// after the window marker was committed. The test restores its private
	// fixture immediately and never touches the canonical fi.* schema.
	var tamperID int64
	var originalScope string
	if err := admin.QueryRow(ctx, `
SELECT sr.source_record_id,sr.scope_id
FROM fi_recovery_projection.source_record sr
JOIN fi_recovery_projection.source_batch sb ON sb.source_batch_id=sr.source_batch_id
JOIN fi_recovery_projection.recorded_generation rg ON rg.recorded_generation_id=sb.recorded_generation_id
WHERE rg.source_id=$1
ORDER BY sr.source_record_id LIMIT 1
`, g.Receipt.Descriptor.SourceID).Scan(&tamperID, &originalScope); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `
UPDATE fi_recovery_projection.source_record SET scope_id='fi-tamper-test'
WHERE source_record_id=$1
`, tamperID); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCompleteBacklogTypedGeneration(ctx, reader, g, limits); err == nil {
		t.Fatal("private source/typed identity tamper was not detected")
	}
	if _, err := admin.Exec(ctx, `
UPDATE fi_recovery_projection.source_record SET scope_id=$2
WHERE source_record_id=$1
`, tamperID, originalScope); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCompleteBacklogTypedGeneration(ctx, reader, g, limits); err != nil {
		t.Fatalf("whole-generation verification not restored after fixture repair: %v", err)
	}
	var typed, records, markers, authoritative int64
	if err := writer.QueryRow(ctx, `
SELECT
 (SELECT count(*) FROM fi_recovery_projection.ntfs_collection_error),
 (SELECT count(*) FROM fi_recovery_projection.source_record),
 (SELECT count(*) FROM fi_recovery.typed_window),
 (SELECT count(*) FROM fi.recorded_generation WHERE source_id=$1)
`, g.Receipt.Descriptor.SourceID).Scan(&typed, &records, &markers, &authoritative); err != nil {
		t.Fatal(err)
	}
	if typed != 3 || records != 6 || markers != 2 || authoritative != 0 {
		t.Fatalf("STOP: typed=%d records=%d windows=%d canonical=%d", typed, records, markers, authoritative)
	}
	var supporting int64
	if err := writer.QueryRow(ctx,
		"SELECT count(*) FROM fi_recovery_projection.supporting_source_collection_error").Scan(&supporting); err != nil {
		t.Fatal(err)
	}
	if supporting != 3 {
		t.Fatalf("missing supporting typed roots: %d", supporting)
	}

	// The late third envelope passes original JSONL parsing and hash
	// validation, but typed payload validation fails AFTER two inserted typed
	// rows. Its entire private typed transaction must roll back.
	late := privateTypedFixture(t, "fi-typed-window-late-reject.iss.local", true)
	lateRoot := privateBacklogTestRoot(t)
	if _, err := MaterializeBacklogWindow(ctx, late, limits, 0, lateRoot); err != nil {
		t.Fatal(err)
	}
	if err := RecordVerifiedBacklogArtifactWindow(ctx, writer, late, limits, 0, lateRoot); err != nil {
		t.Fatal(err)
	}
	if err := StageVerifiedBacklogSourceWindow(ctx, writer, late, limits, 0, lateRoot); err != nil {
		t.Fatal(err)
	}
	if err := StageBacklogTypedWindow(ctx, reader, writer, late, limits, 0, lateRoot); err == nil {
		t.Fatal("invalid late typed payload was accepted")
	}
	var lateShadow, lateMarkers int64
	if err := writer.QueryRow(ctx, `
SELECT
 (SELECT count(*) FROM fi_recovery_projection.recorded_generation WHERE source_id=$1),
 (SELECT count(*) FROM fi_recovery.typed_window WHERE receipt_sha256=decode($2,'hex'))
`, late.Receipt.Descriptor.SourceID, late.ReceiptSHA256).Scan(&lateShadow, &lateMarkers); err != nil {
		t.Fatal(err)
	}
	if lateShadow != 0 || lateMarkers != 0 {
		t.Fatalf("STOP: late typed failure leaked generation/marker: %d/%d", lateShadow, lateMarkers)
	}
	t.Run("file-ntfs-identity-hash-children-across-windows", func(t *testing.T) {
		exerciseBacklogFileWindows(t, ctx, reader, writer)
	})
	t.Run("usn-legacy-cross-window-and-m61-complete-capture", func(t *testing.T) {
		exerciseBacklogUSNWindows(t, ctx, reader, writer)
	})
	t.Run("remaining-five-record-families", func(t *testing.T) {
		exerciseBacklogRemainingFamilies(t, ctx, reader, writer)
	})
	t.Run("whole-generation-recovery-after-reconnect", func(t *testing.T) {
		exerciseBacklogRecoveryRunner(t, ctx, reader, writer)
	})
	t.Run("continuous-family-durable-cross-window-replay", func(t *testing.T) {
		// This fixture exercises the REAL isolated PostgreSQL family writer,
		// not the fake state-machine sink. Both signed source windows are
		// staged first and their partial buffers cross W0 -> W1 without COPY.
		continuous := privateTypedFixture(t, "fi-continuous-family-isolated.iss.local", false)
		continuous.ReceiptSHA256 = strings.Repeat("9", 64)
		continuous.Receipt.TransferSHA256 = strings.Repeat("a", 64)
		continuous.Receipt.Descriptor.GenerationID = "20261101T140000.000000000Z-continuous"
		root := privateBacklogTestRoot(t)
		if err := StageBacklogContinuousFamilyWindows(ctx, writer, continuous, limits, 0, 2, root); err != nil {
			t.Fatalf("continuous SQL W0-W1: %v", err)
		}
		var receipts, typedWindows, stagedRows, authoritative int64
		if err := writer.QueryRow(ctx, `
SELECT
 (SELECT count(*) FROM fi_recovery.projected_source_record WHERE receipt_sha256=decode($1,'hex')),
 (SELECT count(*) FROM fi_recovery.typed_window WHERE receipt_sha256=decode($1,'hex')),
 (SELECT count(*) FROM fi_recovery.pending_source_record WHERE receipt_sha256=decode($1,'hex')),
 (SELECT count(*) FROM fi.recorded_generation WHERE source_id=$2)
`, continuous.ReceiptSHA256, continuous.Receipt.Descriptor.SourceID).
			Scan(&receipts, &typedWindows, &stagedRows, &authoritative); err != nil {
			t.Fatal(err)
		}
		if receipts != 6 || stagedRows != 6 || typedWindows != 2 || authoritative != 0 {
			t.Fatalf("continuous receipts=%d staged=%d typed=%d authoritative=%d", receipts, stagedRows, typedWindows, authoritative)
		}
		// A second complete replay must prove the signed identities and the
		// already committed relational receipts, not duplicate any source.
		if err := StageBacklogContinuousFamilyWindows(ctx, writer, continuous, limits, 0, 2, root); err != nil {
			t.Fatalf("continuous SQL idempotent restart: %v", err)
		}
		var again int64
		if err := writer.QueryRow(ctx, `SELECT count(*) FROM fi_recovery.projected_source_record
WHERE receipt_sha256=decode($1,'hex')`, continuous.ReceiptSHA256).Scan(&again); err != nil {
			t.Fatal(err)
		}
		if again != 6 {
			t.Fatalf("continuous SQL restart duplicated or lost receipts: %d", again)
		}
	})
	t.Run("continuous-family-rollback-on-invalid-typed-child", func(t *testing.T) {
		// The earlier late fixture has durable source W0, but its last
		// NTFSCollectionError payload is invalid. The full OrderedOther
		// transaction must roll back including all projection receipts.
		if err := StageBacklogContinuousFamilyWindows(ctx, writer, late, limits, 0, 1, lateRoot); err == nil {
			t.Fatal("continuous family accepted invalid typed payload")
		}
		var receipts, typed int64
		if err := writer.QueryRow(ctx, `SELECT
 (SELECT count(*) FROM fi_recovery.projected_source_record WHERE receipt_sha256=decode($1,'hex')),
 (SELECT count(*) FROM fi_recovery.typed_window WHERE receipt_sha256=decode($1,'hex'))`,
			late.ReceiptSHA256).Scan(&receipts, &typed); err != nil {
			t.Fatal(err)
		}
		if receipts != 0 || typed != 0 {
			t.Fatalf("continuous family failed transaction leaked projected receipts=%d typed=%d", receipts, typed)
		}
	})
	t.Run("complete-private-to-atomic-canonical-ingest", func(t *testing.T) {
		exerciseBacklogAuthoritativeBridge(t, ctx, admin, reader, writer)
	})
	t.Log("PASS: typed window recovery, complete signed generation proof, missing-window/tamper rejection, late rollback, zero canonical FI rows")
}
