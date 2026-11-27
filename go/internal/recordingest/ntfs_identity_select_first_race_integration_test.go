//go:build fi_ntfs_race_integration

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/jackc/pgx/v5"
)

func TestNTFSObjectSelectFirstRacePostgreSQL(t *testing.T) {
	dsn := os.Getenv("FI_NTFS_CACHE_TEST_DSN")
	expectedData := os.Getenv("FI_NTFS_CACHE_TEST_DATA")
	if dsn == "" || expectedData == "" {
		t.Fatal("isolated PostgreSQL test configuration is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())

	var actualData, listenAddresses string
	if err := admin.QueryRow(ctx, "SHOW data_directory").Scan(&actualData); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, "SHOW listen_addresses").Scan(&listenAddresses); err != nil {
		t.Fatal(err)
	}
	if filepath.Clean(actualData) != filepath.Clean(expectedData) || listenAddresses != "" {
		t.Fatalf("refusing non-isolated cluster: data=%q listen=%q", actualData, listenAddresses)
	}

	for _, statement := range []string{
		`CREATE SCHEMA fi`,
		`CREATE TABLE fi.ntfs_volume (
            ntfs_volume_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            source_id text NOT NULL,
            identity_method_version text NOT NULL,
            volume_guid text NOT NULL,
            volume_serial numeric NOT NULL,
            UNIQUE (source_id, volume_guid, volume_serial))`,
		`CREATE TABLE fi.ntfs_object (
            ntfs_object_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            ntfs_volume_id bigint NOT NULL REFERENCES fi.ntfs_volume(ntfs_volume_id),
            identity_method_version text NOT NULL,
            file_reference_number numeric NOT NULL,
            sequence_number numeric NOT NULL,
            UNIQUE (ntfs_volume_id, file_reference_number, sequence_number))`,
	} {
		if _, err := admin.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}

	var volumeID int64
	if err := admin.QueryRow(ctx, `INSERT INTO fi.ntfs_volume
        (source_id, identity_method_version, volume_guid, volume_serial)
        VALUES ('race-test', 'volume-v1', 'volume-race', 1)
        RETURNING ntfs_volume_id`).Scan(&volumeID); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name            string
		frn             string
		secondMethod    string
		wantMethodError bool
	}{
		{name: "same-method", frn: "900001", secondMethod: "method-v1"},
		{name: "conflicting-method", frn: "900002", secondMethod: "method-v2", wantMethodError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writer, err := pgx.Connect(ctx, dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer writer.Close(context.Background())
			contender, err := pgx.Connect(ctx, dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer contender.Close(context.Background())

			var contenderPID int32
			if err := contender.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&contenderPID); err != nil {
				t.Fatal(err)
			}

			writerTx, err := writer.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer writerTx.Rollback(context.Background())
			identity := records.NTFSObjectIdentity{
				MethodVersion: "method-v1", FileReferenceNumber: tc.frn, SequenceNumber: "7",
			}
			writerCache := newNTFSObjectCache()
			writerCtx := context.WithValue(ctx, ntfsObjectCacheContextKey{}, writerCache)
			writerID, err := ensureNTFSObject(writerCtx, writerTx, volumeID, identity)
			if err != nil || writerID <= 0 {
				t.Fatalf("initial insert: id=%d err=%v", writerID, err)
			}

			contenderTx, err := contender.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer contenderTx.Rollback(context.Background())
			identity.MethodVersion = tc.secondMethod
			contenderCache := newNTFSObjectCache()
			contenderCtx := context.WithValue(ctx, ntfsObjectCacheContextKey{}, contenderCache)
			type result struct {
				id  int64
				err error
			}
			finished := make(chan result, 1)
			go func() {
				id, err := ensureNTFSObject(contenderCtx, contenderTx, volumeID, identity)
				finished <- result{id: id, err: err}
			}()

			// An actual unique-index conflict must block on the writer's
			// uncommitted insertion before the second transaction can finish.
			waitDeadline := time.Now().Add(5 * time.Second)
			blocked := false
			for time.Now().Before(waitDeadline) {
				select {
				case outcome := <-finished:
					t.Fatalf("contender returned before writer committed: id=%d err=%v", outcome.id, outcome.err)
				default:
				}
				var waitType *string
				if err := admin.QueryRow(ctx, `SELECT wait_event_type FROM pg_stat_activity WHERE pid=$1`, contenderPID).Scan(&waitType); err != nil {
					t.Fatal(err)
				}
				if waitType != nil && *waitType == "Lock" {
					blocked = true
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			if !blocked {
				// Release a potentially blocked contender before subtest cleanup.
				_ = writerTx.Rollback(ctx)
				select {
				case <-finished:
				case <-ctx.Done():
				}
				t.Fatal("contender did not reach a PostgreSQL lock wait")
			}

			if err := writerTx.Commit(ctx); err != nil {
				t.Fatal(err)
			}

			var outcome result
			select {
			case outcome = <-finished:
			case <-ctx.Done():
				t.Fatalf("contender remained blocked: %v", ctx.Err())
			}

			if tc.wantMethodError {
				if outcome.err == nil || len(contenderCache.objects) != 0 {
					t.Fatalf("method conflict: id=%d err=%v cache=%d", outcome.id, outcome.err, len(contenderCache.objects))
				}
			} else if outcome.err != nil || outcome.id != writerID || len(contenderCache.objects) != 1 {
				t.Fatalf("same identity: got=%d want=%d err=%v cache=%d", outcome.id, writerID, outcome.err, len(contenderCache.objects))
			}
			if err := contenderTx.Rollback(ctx); err != nil {
				t.Fatal(err)
			}

			var count int
			var method string
			if err := admin.QueryRow(ctx, `SELECT count(*), max(identity_method_version)
                    FROM fi.ntfs_object WHERE ntfs_volume_id=$1
                    AND file_reference_number=$2::text::numeric AND sequence_number=7`,
				volumeID, tc.frn).Scan(&count, &method); err != nil {
				t.Fatal(err)
			}
			if count != 1 || method != "method-v1" {
				t.Fatalf("unique identity invariant: count=%d method=%q", count, method)
			}
		})
	}
}
