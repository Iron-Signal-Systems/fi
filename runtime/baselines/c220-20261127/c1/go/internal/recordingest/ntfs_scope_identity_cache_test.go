package recordingest

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/jackc/pgx/v5"
)

func scopeCacheTestVolume(method string) records.VolumeIdentity {
	return records.VolumeIdentity{
		MethodVersion: method,
		VolumeGUID:    "volume-test",
		VolumeSerial:  "18446744073709551615",
	}
}

func scopeCacheTestRoot() records.GovernedRootIdentity {
	path := base64.RawURLEncoding.EncodeToString(
		[]byte{'C', 0, ':', 0, '\\', 0},
	)

	return records.GovernedRootIdentity{
		ScopeID:                       "scope-a",
		MethodVersion:                 "root-v1",
		VolumeIdentity:                scopeCacheTestVolume("volume-v1"),
		ObjectIdentity:                ntfsCacheTestIdentity("object-v1"),
		RequestedPathUTF16LEBase64URL: path,
		ResolvedPathUTF16LEBase64URL:  path,
	}
}

func TestNTFSScopeCacheVolumeSQLAndConflict(t *testing.T) {
	cache := newNTFSScopeIdentityCache()
	ctx := context.WithValue(
		context.Background(),
		ntfsScopeIdentityCacheContextKey{},
		cache,
	)

	tx := &ntfsCacheTestTx{
		rows: []ntfsCacheTestRow{
			{err: pgx.ErrNoRows},
			{id: 51, method: "volume-v1"},
			{id: 52},
		},
	}

	volume := scopeCacheTestVolume("volume-v1")

	for i := 0; i < 2; i++ {
		id, err := ensureNTFSVolume(ctx, tx, "source-a", volume)
		if err != nil || id != 51 {
			t.Fatalf("lookup %d: id=%d err=%v", i, id, err)
		}
	}

	if len(tx.queries) != 2 {
		t.Fatalf("cached volume performed %d SQL calls", len(tx.queries))
	}

	conflicting := volume
	conflicting.MethodVersion = "volume-v2"

	if _, err := ensureNTFSVolume(
		ctx, tx, "source-a", conflicting,
	); err == nil {
		t.Fatal("cached volume accepted conflicting method")
	}

	if len(tx.queries) != 2 {
		t.Fatal("method conflict unexpectedly queried database")
	}

	id, err := ensureNTFSVolume(ctx, tx, "source-b", volume)
	if err != nil || id != 52 {
		t.Fatalf("source isolation: id=%d err=%v", id, err)
	}

	if len(tx.queries) != 3 || len(cache.volumes) != 2 {
		t.Fatal("volume source isolation or entry count failed")
	}
}

func TestNTFSScopeCacheRootSQLAndExactPaths(t *testing.T) {
	scopeCache := newNTFSScopeIdentityCache()
	objectCache := newNTFSObjectCache()

	root := scopeCacheTestRoot()

	scopeCache.rememberVolume(
		"source-a", root.VolumeIdentity, 10,
	)
	objectCache.remember(
		10, root.ObjectIdentity, 20,
	)

	ctx := context.WithValue(
		context.Background(),
		ntfsScopeIdentityCacheContextKey{},
		scopeCache,
	)
	ctx = context.WithValue(
		ctx, ntfsObjectCacheContextKey{}, objectCache,
	)

	tx := &ntfsCacheTestTx{
		rows: []ntfsCacheTestRow{
			{err: pgx.ErrNoRows},
			{id: 301, method: "root-v1"},
			{id: 302},
			{id: 303},
		},
	}

	for i := 0; i < 2; i++ {
		id, err := ensureGovernedRoot(
			ctx, tx, "source-a", root,
		)
		if err != nil || id != 301 {
			t.Fatalf("root lookup %d: id=%d err=%v", i, id, err)
		}
	}

	if len(tx.queries) != 2 {
		t.Fatalf("cached root performed %d SQL calls", len(tx.queries))
	}

	conflicting := root
	conflicting.MethodVersion = "root-v2"

	if _, err := ensureGovernedRoot(
		ctx, tx, "source-a", conflicting,
	); err == nil {
		t.Fatal("cached root accepted conflicting method")
	}

	if len(tx.queries) != 2 {
		t.Fatal("root conflict unexpectedly queried database")
	}

	differentScope := root
	differentScope.ScopeID = "scope-b"

	id, err := ensureGovernedRoot(
		ctx, tx, "source-a", differentScope,
	)
	if err != nil || id != 302 {
		t.Fatalf("scope isolation: id=%d err=%v", id, err)
	}

	differentPath := root
	differentPath.RequestedPathUTF16LEBase64URL =
		base64.RawURLEncoding.EncodeToString(
			[]byte{'C', 0, ':', 0, '\\', 0, 'X', 0},
		)

	id, err = ensureGovernedRoot(
		ctx, tx, "source-a", differentPath,
	)
	if err != nil || id != 303 {
		t.Fatalf("path isolation: id=%d err=%v", id, err)
	}

	if len(tx.queries) != 4 || len(scopeCache.roots) != 3 {
		t.Fatalf(
			"root SQL=%d cache entries=%d",
			len(tx.queries), len(scopeCache.roots),
		)
	}
}

func TestNTFSScopeCacheSQLFailureNotRemembered(t *testing.T) {
	dbErr := errors.New("simulated database failure")
	cache := newNTFSScopeIdentityCache()

	ctx := context.WithValue(
		context.Background(),
		ntfsScopeIdentityCacheContextKey{},
		cache,
	)

	tx := &ntfsCacheTestTx{
		rows: []ntfsCacheTestRow{
			{err: dbErr},
			{id: 71},
		},
	}

	volume := scopeCacheTestVolume("volume-v1")

	if _, err := ensureNTFSVolume(
		ctx, tx, "source-a", volume,
	); !errors.Is(err, dbErr) {
		t.Fatalf("SQL error was not preserved: %v", err)
	}

	if len(cache.volumes) != 0 {
		t.Fatal("failed volume SQL populated cache")
	}

	id, err := ensureNTFSVolume(
		ctx, tx, "source-a", volume,
	)
	if err != nil || id != 71 {
		t.Fatalf("volume retry: id=%d err=%v", id, err)
	}

	objectCache := newNTFSObjectCache()
	root := scopeCacheTestRoot()

	cache.rememberVolume(
		"source-a", root.VolumeIdentity, 71,
	)
	objectCache.remember(
		71, root.ObjectIdentity, 72,
	)

	ctx = context.WithValue(
		ctx, ntfsObjectCacheContextKey{}, objectCache,
	)

	rootTx := &ntfsCacheTestTx{
		rows: []ntfsCacheTestRow{
			{err: dbErr},
			{id: 73},
		},
	}

	if _, err := ensureGovernedRoot(
		ctx, rootTx, "source-a", root,
	); !errors.Is(err, dbErr) {
		t.Fatalf("root SQL error was not preserved: %v", err)
	}

	if len(cache.roots) != 0 {
		t.Fatal("failed root SQL populated cache")
	}

	id, err = ensureGovernedRoot(
		ctx, rootTx, "source-a", root,
	)
	if err != nil || id != 73 {
		t.Fatalf("root retry: id=%d err=%v", id, err)
	}
}

func TestNTFSScopeCacheGenerationIsolation(t *testing.T) {
	a := newNTFSScopeIdentityCache()
	b := newNTFSScopeIdentityCache()
	volume := scopeCacheTestVolume("v1")

	a.rememberVolume("source-a", volume, 101)

	if _, found, _ := b.lookupVolume(
		"source-a", volume,
	); found {
		t.Fatal("volume cache leaked between generations")
	}

	root := scopeCacheTestRoot()
	requested := []byte{'A', 0}
	resolved := []byte{'B', 0}

	a.rememberRoot(
		"source-a", 101, 201, root,
		requested, resolved, 301,
	)

	if _, found, _ := b.lookupRoot(
		"source-a", 101, 201, root,
		requested, resolved,
	); found {
		t.Fatal("root cache leaked between generations")
	}

	if _, found, _ := a.lookupRoot(
		"source-b", 101, 201, root,
		requested, resolved,
	); found {
		t.Fatal("root cache crossed source boundary")
	}
}

func TestNTFSScopeCacheBoundsAndLongPaths(t *testing.T) {
	cache := newNTFSScopeIdentityCache()

	for i := 0; i < ntfsVolumeCacheMaxEntries+1; i++ {
		volume := scopeCacheTestVolume("v1")
		volume.VolumeGUID = fmt.Sprintf("volume-%d", i)
		cache.rememberVolume(
			"source-a", volume, int64(i+1),
		)
	}

	if len(cache.volumes) != ntfsVolumeCacheMaxEntries {
		t.Fatalf("volume cache unbounded: %d", len(cache.volumes))
	}

	root := scopeCacheTestRoot()

	for i := 0; i < ntfsRootCacheMaxEntries+1; i++ {
		requested := []byte(fmt.Sprintf("path-%d", i))
		cache.rememberRoot(
			"source-a", 10, 20, root,
			requested, []byte("resolved"), int64(i+1),
		)
	}

	if len(cache.roots) != ntfsRootCacheMaxEntries {
		t.Fatalf("root cache unbounded: %d", len(cache.roots))
	}

	other := newNTFSScopeIdentityCache()
	longPath := []byte(strings.Repeat("X", 9000))

	other.rememberRoot(
		"source-a", 10, 20, root,
		longPath, []byte("resolved"), 900,
	)

	if len(other.roots) != 0 {
		t.Fatal("oversized cache key was retained")
	}

	if _, found, err := other.lookupRoot(
		"source-a", 10, 20, root,
		longPath, []byte("resolved"),
	); found || err != nil {
		t.Fatalf(
			"oversized key did not fall through: found=%t err=%v",
			found, err,
		)
	}
}
