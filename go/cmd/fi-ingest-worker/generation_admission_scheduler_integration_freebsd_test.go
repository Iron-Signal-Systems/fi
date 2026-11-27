//go:build freebsd && fi_generation_admission_integration

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/generationready"
	"github.com/Iron-Signal-Systems/fi/go/internal/recordingest"
	"github.com/jackc/pgx/v5"
)

func TestFIGenerationAdmissionSchedulerPreservesPending(t *testing.T) {
	const sourceID = "fi-admission-scheduler-test.iss.local"

	root := filepath.Join(os.Getenv("HOME"), "fi-m1-postgres-20261012")
	if os.Getenv("FI_M1_TEST_POSTGRES_ROOT") != root ||
		os.Getenv("FI_GENERATION_ADMISSION_TEST") != "1" {
		t.Skip("explicit isolated scheduler acceptance not enabled")
	}

	data := filepath.Join(root, "data")
	version, err := os.ReadFile(filepath.Join(data, "PG_VERSION"))
	if err != nil || strings.TrimSpace(string(version)) != "18" {
		t.Fatal("STOP: isolated PostgreSQL 18 fixture missing")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	dsn := fmt.Sprintf(
		"host=%s port=55418 user=fi_m1_admin dbname=fi sslmode=disable connect_timeout=3",
		filepath.Join(root, "socket"),
	)

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())

	var user, database, directory, port, listen string
	err = conn.QueryRow(ctx, `
SELECT current_user, current_database(),
       current_setting('data_directory'),
       current_setting('port'),
       current_setting('listen_addresses')
`).Scan(&user, &database, &directory, &port, &listen)
	if err != nil {
		t.Fatal(err)
	}
	if user != "fi_m1_admin" || database != "fi" ||
		directory != data || port != "55418" || listen != "" {
		t.Fatal("STOP: PostgreSQL fixture identity mismatch")
	}

	// All scheduler database activity is inside a READ ONLY transaction.
	// Any unexpected attempt-journal INSERT must fail instead of persisting.
	if _, err := conn.Exec(ctx, "BEGIN READ ONLY"); err != nil {
		t.Fatal(err)
	}
	defer conn.Exec(context.Background(), "ROLLBACK")

	countState := func() int64 {
		t.Helper()
		var count int64
		err := conn.QueryRow(ctx, `
SELECT
  (SELECT count(*) FROM fi.ingest_journal WHERE source_id=$1)
  +
  (SELECT count(*) FROM fi.recorded_generation WHERE source_id=$1)
`, sourceID).Scan(&count)
		if err != nil {
			t.Fatal(err)
		}
		return count
	}

	if countState() != 0 {
		t.Fatal("STOP: synthetic source already has authoritative state")
	}

	cases := []struct {
		name     string
		records  uint64
		bytes    uint64
		expected string
	}{
		{"record_limit", 101, 500, "max_generation_records=100"},
		{"byte_limit", 50, 1001, "max_generation_data_bytes=1000"},
		{"both_limits", 101, 1001, "max_generation_records=100"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			readyRoot := t.TempDir()

			blockedName := "generation-admission-blocked-" +
				tc.name + ".record.json"
			acceptedName := "generation-admission-accepted-" +
				tc.name + ".record.json"

			for _, name := range []string{blockedName, acceptedName} {
				if _, err := generationready.PublishForSource(
					readyRoot, sourceID, name,
				); err != nil {
					t.Fatal(err)
				}
			}

			plan := recordingest.ReconcilePlan{
				Discovered: 2,
				Accepted:   1,
				Pending:    1,
				Items: []recordingest.ReconcilePlanItem{
					{
						State: recordingest.ReconcileStateAccepted,
						Candidate: recordingest.RecordedReceiptCandidate{
							SourceID:     sourceID,
							GenerationID: "accepted-" + tc.name,
							Path:         filepath.Join("/synthetic", acceptedName),
						},
					},
					{
						State: recordingest.ReconcileStatePending,
						Candidate: recordingest.RecordedReceiptCandidate{
							SourceID:     sourceID,
							GenerationID: "blocked-" + tc.name,
							Path:         filepath.Join("/synthetic", blockedName),
							RecordCount:  tc.records,
							DataBytes:    tc.bytes,
						},
					},
				},
			}

			var attempts uint64

			err := processPlan(
				ctx,
				workerConfig{
					SourceID:               sourceID,
					ReadyRoot:              readyRoot,
					RetryAfter:             15 * time.Minute,
					MaxAttempts:            1,
					MaxGenerationRecords:   100,
					MaxGenerationDataBytes: 1000,
				},
				postgresConnection{connection: conn},
				plan,
				true,
				&attempts,
			)

			if err == nil || !strings.Contains(err.Error(), tc.expected) {
				t.Fatalf("scheduler admission result: %v", err)
			}
			if attempts != 0 {
				t.Fatalf("attempts=%d, want zero", attempts)
			}

			present, err := generationready.ReceiptNamePresentForSource(
				readyRoot, sourceID, blockedName,
			)
			if err != nil || !present {
				t.Fatalf("pending READY marker lost: present=%t err=%v",
					present, err)
			}

			present, err = generationready.ReceiptNamePresentForSource(
				readyRoot, sourceID, acceptedName,
			)
			if err != nil || present {
				t.Fatalf("accepted READY marker not retired: present=%t err=%v",
					present, err)
			}

			if countState() != 0 {
				t.Fatal("authoritative journal or generation state changed")
			}

			t.Logf(
				"PASS scheduler admission=%s attempts=0 pending_marker=present accepted_marker=retired journal_rows=0",
				tc.name,
			)
		})
	}
}
