package recordingest

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/jackc/pgx/v5"
)

type testUSNReasonTx struct {
	pgx.Tx
	calls    int
	queries  []*pgx.QueuedQuery
	closeErr error
}

func (tx *testUSNReasonTx) SendBatch(_ context.Context, batch *pgx.Batch) pgx.BatchResults {
	tx.calls++
	tx.queries = append(tx.queries, batch.QueuedQueries...)
	return testUSNReasonResults{closeErr: tx.closeErr}
}

type testUSNReasonResults struct {
	pgx.BatchResults
	closeErr error
}

func (r testUSNReasonResults) Close() error {
	return r.closeErr
}

func TestFlushUSNReasonBatch(t *testing.T) {
	ctx := context.Background()

	t.Run("empty", func(t *testing.T) {
		tx := &testUSNReasonTx{}
		batch := &pgx.Batch{}

		if err := flushUSNReasonBatch(ctx, tx, batch); err != nil {
			t.Fatal(err)
		}
		if tx.calls != 0 {
			t.Fatalf("empty batch sent %d times", tx.calls)
		}
	})

	t.Run("ordered rows", func(t *testing.T) {
		tx := &testUSNReasonTx{}
		batch := &pgx.Batch{}

		sql := "INSERT INTO fi.usn_object_change_reason VALUES ($1,$2,$3,$4)"
		batch.Queue(sql, int64(42), 2, 1, "DATA_EXTEND")
		batch.Queue(sql, int64(42), 2, 2, "CLOSE")

		if err := flushUSNReasonBatch(ctx, tx, batch); err != nil {
			t.Fatal(err)
		}

		if tx.calls != 1 || batch.Len() != 0 || len(tx.queries) != 2 {
			t.Fatalf("calls=%d remaining=%d queries=%d",
				tx.calls, batch.Len(), len(tx.queries))
		}

		expected := [][]any{
			{int64(42), 2, 1, "DATA_EXTEND"},
			{int64(42), 2, 2, "CLOSE"},
		}

		for i, query := range tx.queries {
			if query.SQL != sql || !reflect.DeepEqual(query.Arguments, expected[i]) {
				t.Fatalf("query %d: SQL=%q args=%v", i, query.SQL, query.Arguments)
			}
		}
	})

	t.Run("database failure", func(t *testing.T) {
		failure := errors.New("injected database failure")
		tx := &testUSNReasonTx{closeErr: failure}
		batch := &pgx.Batch{}

		batch.Queue("INSERT", 1)

		err := flushUSNReasonBatch(ctx, tx, batch)
		if !errors.Is(err, failure) {
			t.Fatalf("expected database failure, got %v", err)
		}

		if batch.Len() != 1 {
			t.Fatal("failed batch unexpectedly cleared")
		}
	})
}
