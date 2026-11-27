//go:build fi_ntfs_benchmark_integration

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/jackc/pgx/v5"
)

const ntfsIdentityBenchmarkObjects = 10000

// BenchmarkNTFSIdentityExistingPostgreSQL compares the exact original
// INSERT-first miss path with ensureNTFSObject's SELECT-first path. Each
// iteration resolves 10,000 different, already-existing identities into a
// fresh generation-local cache, so the benchmark does not accidentally
// measure cache hits. The data is staged in a separate, socket-only cluster.
func BenchmarkNTFSIdentityExistingPostgreSQL(b *testing.B) {
	dsn := os.Getenv("FI_NTFS_CACHE_TEST_DSN")
	expectedData := os.Getenv("FI_NTFS_CACHE_TEST_DATA")
	if dsn == "" || expectedData == "" {
		b.Fatal("isolated PostgreSQL benchmark configuration is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		b.Fatal(err)
	}
	defer conn.Close(context.Background())

	var actualData, listenAddresses, currentDatabase string
	if err := conn.QueryRow(ctx, `SELECT current_setting('data_directory'), current_setting('listen_addresses'), current_database()`).Scan(
		&actualData, &listenAddresses, &currentDatabase,
	); err != nil {
		b.Fatal(err)
	}
	if filepath.Clean(actualData) != filepath.Clean(expectedData) ||
		listenAddresses != "" || currentDatabase != "fi_ntfs_benchmark_test" {
		b.Fatalf("refusing non-isolated benchmark database: data=%q listen=%q database=%q", actualData, listenAddresses, currentDatabase)
	}

	// Fail closed on a reused benchmark database rather than dropping data.
	for _, stmt := range []string{
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
            file_reference_number numeric NOT NULL CHECK (file_reference_number >= 0),
            sequence_number numeric NOT NULL CHECK (sequence_number >= 0),
            UNIQUE (ntfs_volume_id, file_reference_number, sequence_number))`,
	} {
		if _, err := conn.Exec(ctx, stmt); err != nil {
			b.Fatalf("prepare isolated benchmark schema: %v", err)
		}
	}

	var volumeID int64
	if err := conn.QueryRow(ctx, `INSERT INTO fi.ntfs_volume
        (source_id, identity_method_version, volume_guid, volume_serial)
        VALUES ('benchmark', 'volume-v1', 'benchmark-volume', 1)
        RETURNING ntfs_volume_id`).Scan(&volumeID); err != nil {
		b.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `INSERT INTO fi.ntfs_object
        (ntfs_volume_id, identity_method_version, file_reference_number, sequence_number)
        SELECT $1, 'method-v1', 100000000::numeric + g, 7
        FROM generate_series(1, $2::integer) AS g`, volumeID, ntfsIdentityBenchmarkObjects); err != nil {
		b.Fatal(err)
	}

	identities := make([]records.NTFSObjectIdentity, ntfsIdentityBenchmarkObjects)
	for i := range identities {
		identities[i] = records.NTFSObjectIdentity{
			MethodVersion:       "method-v1",
			FileReferenceNumber: fmt.Sprintf("%d", 100000001+i),
			SequenceNumber:      "7",
		}
	}
	benchmark := func(b *testing.B, resolve func(context.Context, pgx.Tx, int64, records.NTFSObjectIdentity) (int64, error)) {
		b.StopTimer()
		for iteration := 0; iteration < b.N; iteration++ {
			tx, err := conn.Begin(ctx)
			if err != nil {
				b.Fatal(err)
			}
			lookupCtx := context.WithValue(ctx, ntfsObjectCacheContextKey{}, newNTFSObjectCache())
			b.StartTimer()
			for i, identity := range identities {
				id, err := resolve(lookupCtx, tx, volumeID, identity)
				if err != nil || id <= 0 {
					b.Fatalf("resolve identity %d: id=%d err=%v", i, id, err)
				}
			}
			b.StopTimer()
			if err := tx.Rollback(ctx); err != nil {
				b.Fatal(err)
			}
		}
	}

	// Reverse order on the second pass to expose cache-warming bias.
	b.Run("insert-first-pass1", func(b *testing.B) {
		benchmark(b, originalInsertFirstNTFSIdentityForBenchmark)
	})
	b.Run("select-first-pass1", func(b *testing.B) {
		benchmark(b, ensureNTFSObject)
	})
	b.Run("select-first-pass2", func(b *testing.B) {
		benchmark(b, ensureNTFSObject)
	})
	b.Run("insert-first-pass2", func(b *testing.B) {
		benchmark(b, originalInsertFirstNTFSIdentityForBenchmark)
	})
}

// Keep the original committed SQL shape as the control. No production code
// uses this helper; it compiles only with the benchmark integration build tag.
func originalInsertFirstNTFSIdentityForBenchmark(ctx context.Context, tx pgx.Tx, volumeID int64, value records.NTFSObjectIdentity) (int64, error) {
	cache, _ := ctx.Value(ntfsObjectCacheContextKey{}).(*ntfsObjectCache)
	if cachedID, found, cacheErr := cache.lookup(volumeID, value); found || cacheErr != nil {
		return cachedID, cacheErr
	}
	var id int64
	err := tx.QueryRow(ctx, `
INSERT INTO fi.ntfs_object (
    ntfs_volume_id, identity_method_version, file_reference_number, sequence_number
)
VALUES ($1,$2,$3::text::numeric,$4::text::numeric)
ON CONFLICT (ntfs_volume_id, file_reference_number, sequence_number)
DO NOTHING
RETURNING ntfs_object_id
`, volumeID, value.MethodVersion, value.FileReferenceNumber, value.SequenceNumber).Scan(&id)
	if err == nil {
		cache.remember(volumeID, value, id)
		return id, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return 0, fmt.Errorf("insert FI NTFS object identity: %w", err)
	}

	var existingMethod string
	if err := tx.QueryRow(ctx, `
SELECT ntfs_object_id, identity_method_version
FROM fi.ntfs_object
WHERE ntfs_volume_id=$1
  AND file_reference_number=$2::text::numeric
  AND sequence_number=$3::text::numeric
`, volumeID, value.FileReferenceNumber, value.SequenceNumber).Scan(&id, &existingMethod); err != nil {
		return 0, fmt.Errorf("reload FI NTFS object identity: %w", err)
	}
	if existingMethod != value.MethodVersion {
		return 0, errors.New("FI NTFS object identity method conflicts with existing relational identity")
	}
	cache.remember(volumeID, value, id)
	return id, nil
}
