//go:build fi_ntfs_identity_prefetch_integration

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/jackc/pgx/v5"
)

// All inserts are rolled back; this test only runs against an explicit
// Unix-socket-only, freshly initialized isolated PostgreSQL database.
func TestNTFSIdentityPrefetchPostgreSQL(t *testing.T) {
	dsn := os.Getenv("FI_IDENTITY_PREFETCH_TEST_DSN")
	expectedData := os.Getenv("FI_IDENTITY_PREFETCH_TEST_DATA")
	if dsn == "" || expectedData == "" {
		t.Fatal("isolated PostgreSQL environment required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())

	// The isolated-cluster owner checks data_directory in the replay script.
	// fi_ingest intentionally lacks permission to read this protected setting.
	// Independently require its Unix-socket endpoint and database identity.
	if _, err := os.Stat(expectedData + "/PG_VERSION"); err != nil {
		t.Fatalf("STOP: isolated PostgreSQL data directory unavailable: %v", err)
	}
	config := conn.Config()
	if config.Host != os.Getenv("FI_IDENTITY_PREFETCH_TEST_SOCKET") || config.Port != 55442 {
		t.Fatalf("STOP: unexpected PostgreSQL endpoint host=%q port=%d", config.Host, config.Port)
	}
	var listen, database, user, port string
	if err := conn.QueryRow(ctx, `SELECT current_setting('listen_addresses'), current_database(), current_user, current_setting('port')`).Scan(&listen, &database, &user, &port); err != nil {
		t.Fatal(err)
	}
	if listen != "" || database != "fi" || user != "fi_ingest" || port != "55442" {
		t.Fatalf("STOP: isolation identity mismatch listen=%q db=%q user=%q port=%q", listen, database, user, port)
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())

	var volume int64
	err = tx.QueryRow(ctx, `INSERT INTO fi.ntfs_volume(source_id,identity_method_version,volume_guid,volume_serial)
        VALUES ('fi-identity-prefetch-isolation','v1','fi-isolated-prefetch-volume',1)
        RETURNING ntfs_volume_id`).Scan(&volume)
	if err != nil {
		t.Fatal(err)
	}

	var existing int64
	err = tx.QueryRow(ctx, `INSERT INTO fi.ntfs_object(ntfs_volume_id,identity_method_version,file_reference_number,sequence_number)
        VALUES ($1,'v1',1001,7) RETURNING ntfs_object_id`, volume).Scan(&existing)
	if err != nil {
		t.Fatal(err)
	}

	object := func(frn, method string) records.NTFSObjectIdentity {
		return records.NTFSObjectIdentity{FileReferenceNumber: frn, SequenceNumber: "7", MethodVersion: method}
	}
	makeRequest := func(frn, method string, originals ...records.NTFSObjectIdentity) *ntfsIdentityPrefetchRequest {
		return &ntfsIdentityPrefetchRequest{
			key: ntfsIdentityPrefetchKey{volumeID: volume, frn: frn, sequence: "7"}, method: method, originals: originals,
		}
	}
	cache := newNTFSObjectCache()
	entries := []*ntfsIdentityPrefetchRequest{
		makeRequest("1001", "v1", object("001001", "v1"), object("1001", "v1")),
		makeRequest("1002", "v1", object("1002", "v1")),
		makeRequest("1003", "v1", object("1003", "v1")),
	}
	if err := prefetchNTFSObjectBatch(ctx, tx, cache, entries); err != nil {
		t.Fatal(err)
	}

	got, found, err := cache.lookup(volume, object("001001", "v1"))
	if err != nil || !found || got != existing {
		t.Fatalf("existing identity id=%d want=%d found=%t err=%v", got, existing, found, err)
	}
	for _, frn := range []string{"1002", "1003"} {
		wanted, found, err := cache.lookup(volume, object(frn, "v1"))
		if err != nil || !found || wanted <= 0 {
			t.Fatalf("new %s unresolved id=%d found=%t err=%v", frn, wanted, found, err)
		}
		var actual int64
		if err := tx.QueryRow(ctx, `SELECT ntfs_object_id FROM fi.ntfs_object WHERE ntfs_volume_id=$1 AND file_reference_number=$2::numeric AND sequence_number=7`, volume, frn).Scan(&actual); err != nil {
			t.Fatal(err)
		}
		if wanted != actual || actual == existing {
			t.Fatalf("new %s has wrong id=%d want=%d", frn, wanted, actual)
		}
	}

	if err := prefetchNTFSObjectBatch(ctx, tx, newNTFSObjectCache(), []*ntfsIdentityPrefetchRequest{
		makeRequest("1001", "v2", object("1001", "v2")),
	}); err == nil || !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("database identity method conflict was not rejected: %v", err)
	}
	var count int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM fi.ntfs_object WHERE ntfs_volume_id=$1`, volume).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Fatalf("batch produced %d identities, expected 3", count)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var remaining int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM fi.ntfs_volume WHERE source_id='fi-identity-prefetch-isolation'`).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatalf("rolled-back volume persisted: %d", remaining)
	}
}
