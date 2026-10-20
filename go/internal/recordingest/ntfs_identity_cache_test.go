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
		rows: []ntfsCacheTestRow{
			{err: pgx.ErrNoRows},
			{id: 42, method: "method-v1"},
		},
	}

	identity := ntfsCacheTestIdentity("method-v1")

	for i := 0; i < 2; i++ {
		id, err := ensureNTFSObject(ctx, tx, 10, identity)
		if err != nil || id != 42 {
			t.Fatalf("lookup %d: id=%d err=%v", i, id, err)
		}
	}

	if len(tx.queries) != 2 {
		t.Fatalf("SQL calls=%d, want 2", len(tx.queries))
	}
	if !strings.Contains(tx.queries[0], "INSERT INTO fi.ntfs_object") ||
		!strings.Contains(tx.queries[1], "SELECT ntfs_object_id") {
		t.Fatal("unexpected SQL sequence")
	}

	conflicting := ntfsCacheTestIdentity("method-v2")
	if _, err := ensureNTFSObject(ctx, tx, 10, conflicting); err == nil {
		t.Fatal("cached identity accepted conflicting method version")
	}
	if len(tx.queries) != 2 {
		t.Fatal("conflicting cache hit unexpectedly queried PostgreSQL")
	}
}

func TestNTFSCacheNewIdentityAndVolumeIsolation(t *testing.T) {
	cache := newNTFSObjectCache()
	ctx := context.WithValue(
		context.Background(), ntfsObjectCacheContextKey{}, cache,
	)
	tx := &ntfsCacheTestTx{
		rows: []ntfsCacheTestRow{{id: 51}, {id: 52}},
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

	if len(tx.queries) != 2 || len(cache.objects) != 2 {
		t.Fatalf("queries=%d entries=%d", len(tx.queries), len(cache.objects))
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
	if len(tx.queries) != 2 {
		t.Fatalf("queries=%d, want 2", len(tx.queries))
	}
}

func TestNTFSCacheDatabaseMethodConflictNotCached(t *testing.T) {
	cache := newNTFSObjectCache()
	ctx := context.WithValue(
		context.Background(), ntfsObjectCacheContextKey{}, cache,
	)
	tx := &ntfsCacheTestTx{
		rows: []ntfsCacheTestRow{
			{err: pgx.ErrNoRows},
			{id: 81, method: "different-method"},
		},
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
		rows: []ntfsCacheTestRow{{id: 91}},
	}
	txB := &ntfsCacheTestTx{
		rows: []ntfsCacheTestRow{{id: 92}},
	}

	idA, errA := ensureNTFSObject(ctxA, txA, 10, identity)
	idB, errB := ensureNTFSObject(ctxB, txB, 10, identity)

	if errA != nil || errB != nil || idA != 91 || idB != 92 {
		t.Fatalf("generation isolation: A=%d/%v B=%d/%v",
			idA, errA, idB, errB)
	}
	if len(txA.queries) != 1 || len(txB.queries) != 1 {
		t.Fatal("separate generations unexpectedly shared cache results")
	}
}

func TestNTFSCacheBounded(t *testing.T) {
	cache := newNTFSObjectCache()

	for i := 0; i < ntfsObjectCacheMaxEntries+1; i++ {
		value := ntfsCacheTestIdentity("method-v1")
		value.FileReferenceNumber = fmt.Sprintf("%d", i+1)
		cache.remember(10, value, int64(i+1))
	}

	if len(cache.objects) != ntfsObjectCacheMaxEntries {
		t.Fatalf("entries=%d, limit=%d",
			len(cache.objects), ntfsObjectCacheMaxEntries)
	}
}
