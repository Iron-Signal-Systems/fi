//go:build fi_ntfs_scope_cache_integration

package recordingest

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestNTFSScopeCachePostgreSQL(t *testing.T) {
	ctx := context.Background()
	dsn := os.Getenv("FI_SCOPE_CACHE_TEST_DSN")
	if dsn == "" {
		t.Fatal("isolated PostgreSQL DSN required")
	}

	db, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close(ctx)

	// Minimal schema preserving the actual identity keys and SQL types.
	ddl := []string{
		`CREATE SCHEMA fi`,
		`CREATE TABLE fi.ntfs_volume (
            ntfs_volume_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            source_id text NOT NULL,
            identity_method_version text NOT NULL,
            volume_guid text NOT NULL,
            volume_serial numeric(20,0) NOT NULL,
            UNIQUE (source_id, volume_guid, volume_serial)
        )`,
		`CREATE TABLE fi.ntfs_object (
            ntfs_object_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            ntfs_volume_id bigint NOT NULL
                REFERENCES fi.ntfs_volume,
            identity_method_version text NOT NULL,
            file_reference_number numeric(20,0) NOT NULL,
            sequence_number numeric(20,0) NOT NULL,
            UNIQUE (
                ntfs_volume_id, file_reference_number, sequence_number
            )
        )`,
		`CREATE TABLE fi.governed_root (
            governed_root_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            source_id text NOT NULL,
            scope_id text NOT NULL,
            containment_method_version text NOT NULL,
            ntfs_volume_id bigint NOT NULL
                REFERENCES fi.ntfs_volume,
            ntfs_object_id bigint NOT NULL
                REFERENCES fi.ntfs_object,
            requested_path_utf16le bytea NOT NULL,
            resolved_path_utf16le bytea NOT NULL,
            UNIQUE (
                source_id, scope_id, ntfs_volume_id,
                ntfs_object_id, requested_path_utf16le,
                resolved_path_utf16le
            )
        )`,
	}

	for _, sql := range ddl {
		if _, err := db.Exec(ctx, sql); err != nil {
			t.Fatalf("schema setup: %v", err)
		}
	}

	newContext := func() (
		context.Context, *ntfsScopeIdentityCache,
	) {
		scope := newNTFSScopeIdentityCache()
		objects := newNTFSObjectCache()

		c := context.WithValue(
			ctx, ntfsScopeIdentityCacheContextKey{}, scope,
		)
		c = context.WithValue(
			c, ntfsObjectCacheContextKey{}, objects,
		)
		return c, scope
	}

	checkEmpty := func() {
		t.Helper()
		var count int64

		err := db.QueryRow(ctx, `
SELECT
    (SELECT count(*) FROM fi.ntfs_volume) +
    (SELECT count(*) FROM fi.ntfs_object) +
    (SELECT count(*) FROM fi.governed_root)
`).Scan(&count)

		if err != nil || count != 0 {
			t.Fatalf("rollback incomplete: %d %v", count, err)
		}
	}

	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())

	c, cache := newContext()
	root := scopeCacheTestRoot()

	volumeID, err := ensureNTFSVolume(
		c, tx, "source-a", root.VolumeIdentity,
	)
	if err != nil {
		t.Fatal(err)
	}

	objectID, err := ensureNTFSObject(
		c, tx, volumeID, root.ObjectIdentity,
	)
	if err != nil {
		t.Fatal(err)
	}
	if objectID <= 0 {
		t.Fatalf("invalid NTFS object ID: %d", objectID)
	}

	rootID, err := ensureGovernedRoot(
		c, tx, "source-a", root,
	)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 10; i++ {
		id, err := ensureGovernedRoot(
			c, tx, "source-a", root,
		)
		if err != nil || id != rootID {
			t.Fatalf(
				"cached root %d: id=%d err=%v", i, id, err,
			)
		}
	}

	if cache.rootHits != 10 ||
		cache.rootMisses != 1 ||
		cache.volumeHits == 0 ||
		len(cache.volumes) != 1 ||
		len(cache.roots) != 1 {
		t.Fatalf("unexpected cache counters: %+v", cache)
	}

	// A fresh cache must still enforce conflicts in existing SQL rows.
	otherContext, otherCache := newContext()

	badVolume := root.VolumeIdentity
	badVolume.MethodVersion = "conflicting-volume-method"

	if _, err := ensureNTFSVolume(
		otherContext, tx, "source-a", badVolume,
	); err == nil {
		t.Fatal("PostgreSQL volume method conflict accepted")
	}

	if len(otherCache.volumes) != 0 {
		t.Fatal("volume conflict populated cache")
	}

	id, err := ensureNTFSVolume(
		otherContext, tx, "source-a", root.VolumeIdentity,
	)
	if err != nil || id != volumeID {
		t.Fatalf("reload volume: %d %v", id, err)
	}

	badRoot := root
	badRoot.MethodVersion = "conflicting-root-method"

	if _, err := ensureGovernedRoot(
		otherContext, tx, "source-a", badRoot,
	); err == nil {
		t.Fatal("PostgreSQL governed-root conflict accepted")
	}

	if len(otherCache.roots) != 0 {
		t.Fatal("governed-root conflict populated cache")
	}

	id, err = ensureGovernedRoot(
		otherContext, tx, "source-a", root,
	)
	if err != nil || id != rootID {
		t.Fatalf("reload governed root: %d %v", id, err)
	}

	// Scope identity and byte-exact paths must remain distinct.
	anotherScope := root
	anotherScope.ScopeID = "scope-b"

	scopeID, err := ensureGovernedRoot(
		c, tx, "source-a", anotherScope,
	)
	if err != nil || scopeID == rootID {
		t.Fatalf("scope isolation: %d %v", scopeID, err)
	}

	changedPath := root
	changedPath.RequestedPathUTF16LEBase64URL =
		base64.RawURLEncoding.EncodeToString(
			[]byte{'C', 0, ':', 0, '\\', 0, 'X', 0},
		)

	pathID, err := ensureGovernedRoot(
		c, tx, "source-a", changedPath,
	)
	if err != nil || pathID == rootID {
		t.Fatalf("exact path isolation: %d %v", pathID, err)
	}

	sourceID, err := ensureGovernedRoot(
		c, tx, "source-b", root,
	)
	if err != nil || sourceID == rootID {
		t.Fatalf("source isolation: %d %v", sourceID, err)
	}

	// An oversized path must still reach PostgreSQL and round-trip.
	longRoot := root
	longBytes := bytes.Repeat([]byte{'Z', 0}, 5000)
	longEncoded := base64.RawURLEncoding.EncodeToString(longBytes)

	longRoot.RequestedPathUTF16LEBase64URL = longEncoded
	longRoot.ResolvedPathUTF16LEBase64URL = longEncoded

	beforeEntries := len(cache.roots)

	longID, err := ensureGovernedRoot(
		c, tx, "source-a", longRoot,
	)
	if err != nil {
		t.Fatalf("long path insertion: %v", err)
	}

	again, err := ensureGovernedRoot(
		c, tx, "source-a", longRoot,
	)
	if err != nil || again != longID {
		t.Fatalf("long path round-trip: %d %v", again, err)
	}

	if len(cache.roots) != beforeEntries {
		t.Fatal("oversized path unexpectedly entered cache")
	}

	var volumes, objects, roots, exactNumeric int64
	err = tx.QueryRow(ctx, `
SELECT
    (SELECT count(*) FROM fi.ntfs_volume),
    (SELECT count(*) FROM fi.ntfs_object),
    (SELECT count(*) FROM fi.governed_root),
    (SELECT count(*) FROM fi.ntfs_volume
      WHERE volume_serial = 18446744073709551615::numeric)
`).Scan(&volumes, &objects, &roots, &exactNumeric)
	if err != nil {
		t.Fatal(err)
	}

	if volumes != 2 || objects != 2 ||
		roots != 5 || exactNumeric != 2 {
		t.Fatalf(
			"relational coverage: volumes=%d objects=%d roots=%d numeric=%d",
			volumes, objects, roots, exactNumeric,
		)
	}

	var exactPath int64
	err = tx.QueryRow(ctx, `
SELECT count(*)
FROM fi.governed_root
WHERE source_id = 'source-a'
  AND requested_path_utf16le = $1
  AND resolved_path_utf16le = $1
`, longBytes).Scan(&exactPath)
	if err != nil || exactPath != 1 {
		t.Fatalf("long-path byte integrity: %d %v", exactPath, err)
	}

	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	checkEmpty()

	// The next transaction gets fresh, independent cache state.
	nextTx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer nextTx.Rollback(context.Background())

	nextContext, nextCache := newContext()

	if _, err := ensureNTFSVolume(
		nextContext, nextTx, "source-a", root.VolumeIdentity,
	); err != nil {
		t.Fatalf("next generation: %v", err)
	}

	if nextCache.volumeMisses != 1 ||
		len(nextCache.volumes) != 1 {
		t.Fatal("next-generation cache state incorrect")
	}

	if err := nextTx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	checkEmpty()

	t.Log("PASS: PostgreSQL identity constraints and conflicts")
	t.Log("PASS: source/scope isolation and exact UTF-16LE paths")
	t.Log("PASS: uint64 numeric and oversized path persistence")
	t.Log("PASS: transaction rollback and generation isolation")
}
