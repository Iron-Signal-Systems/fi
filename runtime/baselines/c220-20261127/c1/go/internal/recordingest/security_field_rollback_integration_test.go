//go:build freebsd && fi_copy_latency_replay_integration && fi_security_rollback_integration

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Isolated PostgreSQL acceptance for atomic rollback following a late failure
// in the streaming Windows Security event-field COPY path. This test is NOT
// included in the normal test suite and changes no production source files.
package recordingest

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
	"github.com/jackc/pgx/v5"
)

const (
	securityRollbackEvents = 1024
	securityRollbackFields = 33
)

// rollbackFixtureCounts reads relational table counts, excluding ingest_journal:
// rejected attempts are audited separately and intentionally survive rollback
// until this test's source-owned cleanup removes them.
func rollbackFixtureCounts(t *testing.T, ctx context.Context, admin *pgx.Conn) [6]int64 {
	t.Helper()
	var counts [6]int64
	err := admin.QueryRow(ctx, `
SELECT (SELECT count(*) FROM fi.recorded_generation),
       (SELECT count(*) FROM fi.source_batch),
       (SELECT count(*) FROM fi.source_record),
       (SELECT count(*) FROM fi.windows_security_event),
       (SELECT count(*) FROM fi.windows_security_event_scope),
       (SELECT count(*) FROM fi.windows_security_event_field)`).Scan(
		&counts[0], &counts[1], &counts[2], &counts[3], &counts[4], &counts[5],
	)
	if err != nil {
		t.Fatalf("read isolated relational counts: %v", err)
	}
	return counts
}

// TestSecurityFieldLateCopyFailureRollsBackGeneration signs one complete source
// generation and deliberately puts a PostgreSQL-invalid NUL in its last field.
// The first two 16,384-row field COPY chunks must complete before the final
// 1,024-row chunk fails. The production ingestion path must then roll back
// every parent, source, scope, and field row in the generation transaction.
// The injected invalid value is test data only, never a production code hook.
func TestSecurityFieldLateCopyFailureRollsBackGeneration(t *testing.T) {
	if os.Getenv("FI_M1_ALLOW_ISOLATED_WRITES") != "1" {
		t.Skip("isolated PostgreSQL write approval absent")
	}
	root := filepath.Join(os.Getenv("HOME"), "fi-m1-postgres-20261012")
	if os.Getenv("FI_M1_TEST_POSTGRES_ROOT") != root {
		t.Fatal("STOP: unexpected isolated PostgreSQL root")
	}
	version, err := os.ReadFile(filepath.Join(root, "data", "PG_VERSION"))
	if err != nil || string(version) != "18\n" {
		t.Fatal("STOP: isolated PostgreSQL 18 marker missing")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
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
		t.Fatalf("STOP: isolated fixture has %d relational tables, want 49", state.RelationalTables)
	}

	sourceID := securityReplaySource
	var existing int64
	err = admin.QueryRow(ctx, `SELECT count(*) FROM fi.recorded_generation WHERE source_id=$1`, sourceID).Scan(&existing)
	if err != nil || existing != 0 {
		t.Fatalf("STOP: replay source is not isolated: existing=%d err=%v", existing, err)
	}
	before := rollbackFixtureCounts(t, ctx, admin)

	// Build the same kind of signed, custody-checked generation used by the
	// successful security replay. Only the last field of the last event is
	// invalid as PostgreSQL text; source integrity and signature remain valid.
	fixtureRoot := t.TempDir()
	for _, name := range []string{
		"custody", "recorded", "ready",
		filepath.Join("recorded", "sources", sourceID),
	} {
		if err := os.MkdirAll(filepath.Join(fixtureRoot, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z")
	input := make([]spool.Record, 0, securityRollbackEvents)
	for event := 0; event < securityRollbackEvents; event++ {
		fields := make([]records.WindowsSecurityEventField, 0, securityRollbackFields)
		for ordinal := 0; ordinal < securityRollbackFields; ordinal++ {
			value := fmt.Sprintf("value-%02d", ordinal)
			if event == securityRollbackEvents-1 && ordinal == securityRollbackFields-1 {
				value = "\x00" // Third field COPY must fail; first two complete.
			}
			fields = append(fields, records.WindowsSecurityEventField{
				Name: fmt.Sprintf("Field%02d", ordinal), Value: value,
			})
		}
		eventRecordID := strconv.Itoa(200000000 + event)
		observation := records.WindowsSecurityEventObservation{
			ObservedAt:       now,
			CollectionMethod: records.WindowsSecurityCollectionMethod,
			Channel:          "Security",
			Provider:         "Microsoft-Windows-Security-Auditing",
			EventID:          "4663",
			EventRecordID:    eventRecordID,
			TimeCreated:      now,
			Computer:         "fi-rollback-test.iss.local",
			AuditResult:      records.WindowsSecurityAuditSuccess,
			ScopeBasis:       records.WindowsSecurityScopePathMatched,
			MatchedScopes: []records.WindowsSecurityMatchedScope{
				{ScopeID: "security-replay", GovernedRoot: `C:\FI-Latency-Test`},
			},
			Fields: fields,
			RawXML: fmt.Sprintf("<Event><RecordID>%s</RecordID></Event>", eventRecordID),
		}
		if err := records.ValidateWindowsSecurityEventObservation(observation); err != nil {
			t.Fatalf("invalid source event %d: %v", event, err)
		}
		payload, err := json.Marshal(observation)
		if err != nil {
			t.Fatal(err)
		}
		input = append(input, spool.Record{
			Version: spool.RecordVersion, RecordKind: "WindowsSecurityEvent",
			ScopeID: "security-replay", WrittenAt: now, Payload: payload,
		})
	}

	signed := m1WriteSignedGenerationRecords(t, fixtureRoot, sourceID, input)
	attemptID := "security-field-rollback-" + signed.GenerationID
	t.Cleanup(func() {
		cleanupSecurityReplay(t, admin, sourceID, signed.GenerationID, attemptID)
	})
	config := GenerationLoadConfig{
		CustodyRoot:       filepath.Join(fixtureRoot, "custody"),
		RecordedRoot:      filepath.Join(fixtureRoot, "recorded"),
		SourceNamespaces:  true,
		SourceID:          sourceID,
		MaxCanonicalBytes: 64 << 20,
		MaxEncodedBytes:   64 << 20,
		MaxManifestBytes:  1 << 20,
	}
	prepared, err := loadRecordedGenerationWithTrust(config, signed.GenerationID,
		func(source string) (generationTrustBundle, error) {
			if source != sourceID {
				return generationTrustBundle{}, fmt.Errorf("unexpected fixture source %q", source)
			}
			return signed.Trust, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	if prepared.Receipt.RecordCount != securityRollbackEvents || len(prepared.Batches) != 1 {
		t.Fatal("STOP: signed rollback fixture receipt mismatch")
	}
	if err := WriteAttemptStarted(ctx, runtime, attemptID, sourceID, signed.GenerationID); err != nil {
		t.Fatal(err)
	}

	result, err := IngestPreparedGeneration(ctx, runtime, attemptID, prepared)
	if err == nil || !strings.Contains(err.Error(), "FI Security bulk fields streaming COPY") {
		t.Fatalf("expected late security field COPY failure, result=%+v err=%v", result, err)
	}
	if result.RecordsCommitted != 0 || result.Outcome == "Accepted" {
		t.Fatalf("failed generation claimed committed records: %+v", result)
	}

	after := rollbackFixtureCounts(t, ctx, admin)
	if after != before {
		t.Fatalf("atomic rollback failed: counts before=%v after=%v", before, after)
	}
	err = admin.QueryRow(ctx, `SELECT count(*) FROM fi.recorded_generation WHERE source_id=$1`, sourceID).Scan(&existing)
	if err != nil || existing != 0 {
		t.Fatalf("failed generation survived: source generations=%d err=%v", existing, err)
	}
	var rejected int64
	err = admin.QueryRow(ctx, `
SELECT count(*) FROM fi.ingest_journal
WHERE attempt_id=$1 AND source_id=$2 AND generation_id=$3
  AND outcome='Rejected' AND records_committed=0`, attemptID, sourceID, signed.GenerationID).Scan(&rejected)
	if err != nil || rejected != 1 {
		t.Fatalf("missing rejected terminal audit: count=%d err=%v", rejected, err)
	}
	t.Logf("PASS: late field COPY failure rejected; rollback preserved source+projection counts %v; rejected journal recorded", before)
}
