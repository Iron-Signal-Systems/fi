package recordingest

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestUSNReasonBatchPostgreSQL(t *testing.T) {
	dsn := os.Getenv("FI_USN_REASON_BATCH_TEST_DSN")
	if dsn == "" {
		t.Skip("disposable PostgreSQL not configured")
	}

	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)

	statements := []string{
		"CREATE SCHEMA fi",
		`CREATE TABLE fi.usn_object_change (
            source_record_id bigint NOT NULL,
            change_ordinal integer NOT NULL,
            PRIMARY KEY (source_record_id, change_ordinal)
        )`,
		`CREATE TABLE fi.usn_object_change_reason (
            source_record_id bigint NOT NULL,
            change_ordinal integer NOT NULL,
            reason_ordinal integer NOT NULL,
            reason_name text NOT NULL,
            PRIMARY KEY (source_record_id, change_ordinal, reason_ordinal),
            FOREIGN KEY (source_record_id, change_ordinal)
            REFERENCES fi.usn_object_change
        )`,
	}

	for _, sql := range statements {
		if _, err := conn.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}

	insert := `INSERT INTO fi.usn_object_change_reason
        (source_record_id, change_ordinal, reason_ordinal, reason_name)
        VALUES ($1,$2,$3,$4)`

	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx,
		"INSERT INTO fi.usn_object_change VALUES (42,1)"); err != nil {
		t.Fatal(err)
	}

	var batch pgx.Batch
	batch.Queue(insert, int64(42), 1, 1, "CLOSE")
	batch.Queue(insert, int64(42), 1, 2, "DATA_EXTEND")

	if err := flushUSNReasonBatch(ctx, tx, &batch); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	var count int
	var names string
	err = conn.QueryRow(ctx, `
        SELECT count(*),
            string_agg(reason_name, ',' ORDER BY reason_ordinal)
        FROM fi.usn_object_change_reason
        WHERE source_record_id = 42
    `).Scan(&count, &names)

	if err != nil || count != 2 ||
		names != "CLOSE,DATA_EXTEND" {
		t.Fatalf("rows=%d names=%q error=%v", count, names, err)
	}

	bad, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Rollback(ctx)

	if _, err := bad.Exec(ctx,
		"INSERT INTO fi.usn_object_change VALUES (43,1)"); err != nil {
		t.Fatal(err)
	}

	var duplicate pgx.Batch
	duplicate.Queue(insert, int64(43), 1, 1, "CLOSE")
	duplicate.Queue(insert, int64(43), 1, 1, "DATA_EXTEND")

	if err := flushUSNReasonBatch(ctx, bad, &duplicate); err == nil {
		t.Fatal("duplicate ordinal accepted")
	}

	if err := bad.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	err = conn.QueryRow(ctx,
		"SELECT count(*) FROM fi.usn_object_change WHERE source_record_id=43",
	).Scan(&count)

	if err != nil || count != 0 {
		t.Fatalf("rollback count=%d error=%v", count, err)
	}
}
