//go:build fi_ntfs_cache_integration

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/jackc/pgx/v5"
)

func TestNTFSObjectCachePostgreSQL(t *testing.T) {
	dsn := os.Getenv("FI_NTFS_CACHE_TEST_DSN")
	expectedData := os.Getenv("FI_NTFS_CACHE_TEST_DATA")
	if dsn == "" || expectedData == "" {
		t.Fatal("isolated PostgreSQL test configuration is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())

	// Refuse to create tables unless connected to the exact
	// isolated data directory and a Unix-socket-only server.
	var actualData, listenAddresses string
	if err := conn.QueryRow(ctx, "SHOW data_directory").Scan(&actualData); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRow(ctx, "SHOW listen_addresses").Scan(&listenAddresses); err != nil {
		t.Fatal(err)
	}
	if filepath.Clean(actualData) != filepath.Clean(expectedData) ||
		listenAddresses != "" {
		t.Fatalf("refusing non-isolated cluster: data=%q listen=%q",
			actualData, listenAddresses)
	}

	for _, sql := range []string{
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
            ntfs_volume_id bigint NOT NULL
                REFERENCES fi.ntfs_volume(ntfs_volume_id),
            identity_method_version text NOT NULL,
            file_reference_number numeric NOT NULL
                CHECK (file_reference_number >= 0),
            sequence_number numeric NOT NULL
                CHECK (sequence_number >= 0),
            UNIQUE (ntfs_volume_id, file_reference_number, sequence_number))`,
	} {
		if _, err := conn.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}

	volume := func(guid string, serial int) int64 {
		t.Helper()
		var id int64
		err := conn.QueryRow(ctx, `INSERT INTO fi.ntfs_volume
          (source_id, identity_method_version, volume_guid, volume_serial)
          VALUES ('lab', 'volume-v1', $1, $2)
          RETURNING ntfs_volume_id`, guid, serial).Scan(&id)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}

	volA := volume("volume-A", 1)
	volB := volume("volume-B", 2)

	object := func(vol int64, frn, method string) int64 {
		t.Helper()
		var id int64
		err := conn.QueryRow(ctx, `INSERT INTO fi.ntfs_object
          (ntfs_volume_id, identity_method_version,
           file_reference_number, sequence_number)
          VALUES ($1, $2, $3::text::numeric, 7)
          RETURNING ntfs_object_id`, vol, method, frn).Scan(&id)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}

	existing := object(volA, "12345", "method-v1")
	object(volA, "12347", "other-method")

	identity := func(frn, method string) records.NTFSObjectIdentity {
		return records.NTFSObjectIdentity{
			MethodVersion:       method,
			FileReferenceNumber: frn,
			SequenceNumber:      "7",
		}
	}

	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())

	cache := newNTFSObjectCache()
	cacheCtx := context.WithValue(ctx, ntfsObjectCacheContextKey{}, cache)

	// Existing database identity and repeat lookup.
	for i := 0; i < 2; i++ {
		got, err := ensureNTFSObject(
			cacheCtx, tx, volA, identity("12345", "method-v1"),
		)
		if err != nil || got != existing {
			t.Fatalf("existing identity: id=%d err=%v", got, err)
		}
	}
	if cache.hits != 1 {
		t.Fatalf("cache hits=%d, expected 1", cache.hits)
	}

	// A cached identity must reject a different method.
	_, err = ensureNTFSObject(
		cacheCtx, tx, volA, identity("12345", "conflicting-method"),
	)
	if err == nil || !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("cached identity conflict: %v", err)
	}

	// New identity, followed by a cache hit.
	newIdentity := identity("12346", "method-v1")
	inserted, err := ensureNTFSObject(cacheCtx, tx, volA, newIdentity)
	if err != nil || inserted <= 0 {
		t.Fatalf("insert new identity: id=%d err=%v", inserted, err)
	}
	got, err := ensureNTFSObject(cacheCtx, tx, volA, newIdentity)
	if err != nil || got != inserted {
		t.Fatalf("repeat new identity: id=%d err=%v", got, err)
	}

	// Existing database method conflict must still fail.
	_, err = ensureNTFSObject(
		cacheCtx, tx, volA, identity("12347", "method-v1"),
	)
	if err == nil || !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("database identity conflict: %v", err)
	}

	// Same FRN and sequence, different volume.
	got, err = ensureNTFSObject(
		cacheCtx, tx, volB, identity("12345", "method-v1"),
	)
	if err != nil || got == existing {
		t.Fatalf("volume isolation: id=%d err=%v", got, err)
	}

	// Roll back newly inserted identities.
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	var count int
	err = conn.QueryRow(ctx, `SELECT count(*)
        FROM fi.ntfs_object
        WHERE ntfs_volume_id=$1 AND file_reference_number=12346`,
		volA).Scan(&count)
	if err != nil || count != 0 {
		t.Fatalf("rollback count=%d err=%v", count, err)
	}

	// A new transaction must not reuse the rolled-back ID.
	tx2, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx2.Rollback(context.Background())

	secondCache := newNTFSObjectCache()
	ctx2 := context.WithValue(ctx, ntfsObjectCacheContextKey{}, secondCache)

	insertedAgain, err := ensureNTFSObject(
		ctx2, tx2, volA, newIdentity,
	)
	if err != nil || insertedAgain <= 0 || insertedAgain == inserted {
		t.Fatalf("post-rollback identity=%d previous=%d err=%v",
			insertedAgain, inserted, err)
	}
	if err := tx2.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	// PostgreSQL failure must never populate the cache.
	tx3, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx3.Rollback(context.Background())

	failedCache := newNTFSObjectCache()
	ctx3 := context.WithValue(ctx, ntfsObjectCacheContextKey{}, failedCache)

	_, err = ensureNTFSObject(
		ctx3, tx3, -1, identity("12348", "method-v1"),
	)
	if err == nil {
		t.Fatal("foreign-key violation was accepted")
	}
	if len(failedCache.objects) != 0 {
		t.Fatal("failed database insert populated the cache")
	}
	if err := tx3.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	t.Log("PASS: existing, new, conflict, isolation, rollback and database failure")
}
