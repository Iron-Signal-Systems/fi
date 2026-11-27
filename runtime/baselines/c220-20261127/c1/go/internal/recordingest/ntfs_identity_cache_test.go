package recordingest

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/jackc/pgx/v5"
)

type ntfsCacheTestRow struct {
	id     int64
	method string
	err    error
}

func (r ntfsCacheTestRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) != 1 && len(dest) != 2 {
		return fmt.Errorf("unexpected Scan argument count: %d", len(dest))
	}
	id, ok := dest[0].(*int64)
	if !ok {
		return errors.New("first Scan destination is not *int64")
	}
	*id = r.id
	if len(dest) == 2 {
		method, ok := dest[1].(*string)
		if !ok {
			return errors.New("second Scan destination is not *string")
		}
		*method = r.method
	}
	return nil
}

type ntfsCacheTestTx struct {
	pgx.Tx
	rows    []ntfsCacheTestRow
	queries []string
}

func (tx *ntfsCacheTestTx) QueryRow(
	_ context.Context, sql string, _ ...any,
) pgx.Row {
	tx.queries = append(tx.queries, sql)
	if len(tx.rows) == 0 {
		return ntfsCacheTestRow{
			err: errors.New("unexpected additional SQL query"),
		}
	}
	row := tx.rows[0]
	tx.rows = tx.rows[1:]
	return row
}

func ntfsCacheTestIdentity(method string) records.NTFSObjectIdentity {
	return records.NTFSObjectIdentity{
		MethodVersion:       method,
		FileReferenceNumber: "12345",
		SequenceNumber:      "7",
	}
}

func TestNTFSCacheExistingIdentityAndConflict(t *testing.T) {
	cache := newNTFSObjectCache()
	ctx := context.WithValue(
		context.Background(), ntfsObjectCacheContextKey{}, cache,
	)
	tx := &ntfsCacheTestTx{
		rows: []ntfsCacheTestRow{{id: 42, method: "method-v1"}},
	}

	identity := ntfsCacheTestIdentity("method-v1")

	for i := 0; i < 2; i++ {
		id, err := ensureNTFSObject(ctx, tx, 10, identity)
		if err != nil || id != 42 {
			t.Fatalf("lookup %d: id=%d err=%v", i, id, err)
		}
	}

	if len(tx.queries) != 1 {
		t.Fatalf("SQL calls=%d, want 1", len(tx.queries))
	}
	if !strings.Contains(tx.queries[0], "SELECT ntfs_object_id") {
		t.Fatal("existing identity must use SELECT without INSERT")
	}

	conflicting := ntfsCacheTestIdentity("method-v2")
	if _, err := ensureNTFSObject(ctx, tx, 10, conflicting); err == nil {
		t.Fatal("cached identity accepted conflicting method version")
	}
	if len(tx.queries) != 1 {
		t.Fatal("conflicting cache hit unexpectedly queried PostgreSQL")
	}
}

func TestNTFSCacheNewIdentityAndVolumeIsolation(t *testing.T) {
	cache := newNTFSObjectCache()
	ctx := context.WithValue(
		context.Background(), ntfsObjectCacheContextKey{}, cache,
	)
	tx := &ntfsCacheTestTx{
		rows: []ntfsCacheTestRow{
			{err: pgx.ErrNoRows}, {id: 51},
			{err: pgx.ErrNoRows}, {id: 52},
		},
	}
	identity := ntfsCacheTestIdentity("method-v1")

	for _, tc := range []struct {
		volume int64
		wantID int64
	}{
		{10, 51},
		{10, 51},
		{11, 52},
	} {
		id, err := ensureNTFSObject(ctx, tx, tc.volume, identity)
		if err != nil || id != tc.wantID {
			t.Fatalf("volume=%d id=%d err=%v", tc.volume, id, err)
		}
	}

	if len(tx.queries) != 4 || len(cache.objects) != 2 {
		t.Fatalf("queries=%d entries=%d", len(tx.queries), len(cache.objects))
	}
	for i := 0; i < len(tx.queries); i += 2 {
		if !strings.Contains(tx.queries[i], "SELECT ntfs_object_id") ||
			!strings.Contains(tx.queries[i+1], "INSERT INTO fi.ntfs_object") {
			t.Fatalf("new identity SQL sequence at %d is not SELECT then INSERT", i)
		}
	}
}

func TestNTFSCacheDatabaseErrorNotCached(t *testing.T) {
	dbErr := errors.New("simulated PostgreSQL failure")
	cache := newNTFSObjectCache()
	ctx := context.WithValue(
		context.Background(), ntfsObjectCacheContextKey{}, cache,
	)
	tx := &ntfsCacheTestTx{
		rows: []ntfsCacheTestRow{
			{err: dbErr},
			{err: pgx.ErrNoRows},
			{id: 75},
		},
	}
	identity := ntfsCacheTestIdentity("method-v1")

	if _, err := ensureNTFSObject(ctx, tx, 10, identity); !errors.Is(err, dbErr) {
		t.Fatalf("database error not preserved: %v", err)
	}
	if len(cache.objects) != 0 {
		t.Fatal("database failure populated cache")
	}

	id, err := ensureNTFSObject(ctx, tx, 10, identity)
	if err != nil || id != 75 {
		t.Fatalf("retry: id=%d err=%v", id, err)
	}
	if len(tx.queries) != 3 {
		t.Fatalf("queries=%d, want 3", len(tx.queries))
	}
}

func TestNTFSCacheDatabaseMethodConflictNotCached(t *testing.T) {
	cache := newNTFSObjectCache()
	ctx := context.WithValue(
		context.Background(), ntfsObjectCacheContextKey{}, cache,
	)
	tx := &ntfsCacheTestTx{
		rows: []ntfsCacheTestRow{{id: 81, method: "different-method"}},
	}

	if _, err := ensureNTFSObject(
		ctx, tx, 10, ntfsCacheTestIdentity("method-v1"),
	); err == nil {
		t.Fatal("database identity conflict was accepted")
	}
	if len(cache.objects) != 0 {
		t.Fatal("conflicting database identity populated cache")
	}
}

func TestNTFSCacheSeparateGenerationContexts(t *testing.T) {
	identity := ntfsCacheTestIdentity("method-v1")
	cacheA := newNTFSObjectCache()
	cacheB := newNTFSObjectCache()

	ctxA := context.WithValue(
		context.Background(), ntfsObjectCacheContextKey{}, cacheA,
	)
	ctxB := context.WithValue(
		context.Background(), ntfsObjectCacheContextKey{}, cacheB,
	)

	txA := &ntfsCacheTestTx{
		rows: []ntfsCacheTestRow{{err: pgx.ErrNoRows}, {id: 91}},
	}
	txB := &ntfsCacheTestTx{
		rows: []ntfsCacheTestRow{{err: pgx.ErrNoRows}, {id: 92}},
	}

	idA, errA := ensureNTFSObject(ctxA, txA, 10, identity)
	idB, errB := ensureNTFSObject(ctxB, txB, 10, identity)

	if errA != nil || errB != nil || idA != 91 || idB != 92 {
		t.Fatalf("generation isolation: A=%d/%v B=%d/%v",
			idA, errA, idB, errB)
	}
	if len(txA.queries) != 2 || len(txB.queries) != 2 {
		t.Fatal("separate generations unexpectedly shared cache results")
	}
}

func TestNTFSCacheConcurrentInsertion(t *testing.T) {
	for _, tc := range []struct {
		name    string
		method  string
		wantErr bool
	}{
		{name: "same-method", method: "method-v1"},
		{name: "conflicting-method", method: "other-method", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cache := newNTFSObjectCache()
			ctx := context.WithValue(context.Background(), ntfsObjectCacheContextKey{}, cache)
			tx := &ntfsCacheTestTx{rows: []ntfsCacheTestRow{
				{err: pgx.ErrNoRows},
				{err: pgx.ErrNoRows},
				{id: 100, method: tc.method},
			}}
			id, err := ensureNTFSObject(ctx, tx, 10, ntfsCacheTestIdentity("method-v1"))
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "conflicts") || len(cache.objects) != 0 {
					t.Fatalf("concurrent method conflict: id=%d err=%v cache=%d", id, err, len(cache.objects))
				}
			} else if err != nil || id != 100 || len(cache.objects) != 1 {
				t.Fatalf("concurrent identity: id=%d err=%v cache=%d", id, err, len(cache.objects))
			}
			if len(tx.queries) != 3 ||
				!strings.Contains(tx.queries[0], "SELECT ntfs_object_id") ||
				!strings.Contains(tx.queries[1], "INSERT INTO fi.ntfs_object") ||
				!strings.Contains(tx.queries[2], "SELECT ntfs_object_id") {
				t.Fatalf("unexpected concurrent insertion SQL sequence: %v", tx.queries)
			}
		})
	}
}

func TestNTFSCacheInsertErrorNotCached(t *testing.T) {
	dbErr := errors.New("simulated identity insert failure")
	cache := newNTFSObjectCache()
	ctx := context.WithValue(context.Background(), ntfsObjectCacheContextKey{}, cache)
	tx := &ntfsCacheTestTx{rows: []ntfsCacheTestRow{
		{err: pgx.ErrNoRows},
		{err: dbErr},
	}}
	_, err := ensureNTFSObject(ctx, tx, 10, ntfsCacheTestIdentity("method-v1"))
	if !errors.Is(err, dbErr) || len(cache.objects) != 0 {
		t.Fatalf("insert failure: err=%v cache=%d", err, len(cache.objects))
	}
}

func TestNTFSCacheBounded(t *testing.T) {
	cache := newNTFSObjectCache()

	// Exceed the old 262,144-entry ceiling by more than one prefetch batch.
	// The cache must stay bounded without freezing out every subsequent key.
	const extra = 1025
	for i := 0; i < ntfsObjectCacheMaxEntries+extra; i++ {
		value := ntfsCacheTestIdentity("method-v1")
		value.FileReferenceNumber = fmt.Sprintf("%d", i+1)
		cache.remember(10, value, int64(i+1))
	}

	if len(cache.objects) != ntfsObjectCacheMaxEntries ||
		len(cache.order) != ntfsObjectCacheMaxEntries {
		t.Fatalf("entries=%d fifo=%d limit=%d",
			len(cache.objects), len(cache.order), ntfsObjectCacheMaxEntries)
	}
	if cache.evictions != extra {
		t.Fatalf("evictions=%d, want %d", cache.evictions, extra)
	}

	oldest := ntfsCacheTestIdentity("method-v1")
	oldest.FileReferenceNumber = "1"
	if _, found, err := cache.lookup(10, oldest); err != nil || found {
		t.Fatalf("oldest identity must be evicted: found=%t err=%v", found, err)
	}

	newest := ntfsCacheTestIdentity("method-v1")
	newest.FileReferenceNumber = fmt.Sprintf("%d", ntfsObjectCacheMaxEntries+extra)
	got, found, err := cache.lookup(10, newest)
	if err != nil || !found || got != ntfsObjectCacheMaxEntries+extra {
		t.Fatalf("newest identity missing: id=%d found=%t err=%v", got, found, err)
	}

	// Remembering an existing identity cannot evict an unrelated one.
	cache.remember(10, newest, got)
	if cache.evictions != extra {
		t.Fatalf("existing identity triggered eviction: %d", cache.evictions)
	}

	// A different method for a cached identity must still fail closed.
	newest.MethodVersion = "method-v2"
	if _, found, err := cache.lookup(10, newest); !found || err == nil {
		t.Fatalf("cached method conflict not detected: found=%t err=%v", found, err)
	}
}
