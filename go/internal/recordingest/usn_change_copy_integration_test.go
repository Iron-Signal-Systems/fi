//go:build fi_usn_change_copy_integration

package recordingest

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestUSNChangeCopyPostgreSQL(t *testing.T) {
	ctx := context.Background()
	dsn := os.Getenv("FI_USN_COPY_TEST_DSN")
	if dsn == "" {
		t.Fatal("isolated PostgreSQL DSN required")
	}

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)

	ddl := []string{
		`CREATE SCHEMA fi`,
		`CREATE TABLE fi.ntfs_object (
            ntfs_object_id bigint PRIMARY KEY
        )`,
		`CREATE TABLE fi.usn_object_observation (
            source_record_id bigint PRIMARY KEY
        )`,
		`CREATE TABLE fi.usn_object_change (
            source_record_id bigint NOT NULL
                REFERENCES fi.usn_object_observation,
            change_ordinal integer NOT NULL,
            major_version integer NOT NULL,
            minor_version integer NOT NULL,
            usn numeric NOT NULL,
            event_timestamp timestamptz NOT NULL,
            reason_raw bigint NOT NULL,
            source_info_raw bigint NOT NULL,
            security_id bigint NOT NULL,
            file_attributes_raw bigint NOT NULL,
            file_name_utf16le bytea NOT NULL,
            file_ntfs_object_id bigint NOT NULL
                REFERENCES fi.ntfs_object,
            parent_ntfs_object_id bigint NOT NULL
                REFERENCES fi.ntfs_object,
            PRIMARY KEY (source_record_id, change_ordinal)
        )`,
		`CREATE TABLE fi.usn_object_change_reason (
            source_record_id bigint NOT NULL,
            change_ordinal integer NOT NULL,
            reason_ordinal integer NOT NULL,
            reason_name text NOT NULL,
            PRIMARY KEY (
                source_record_id, change_ordinal, reason_ordinal
            ),
            FOREIGN KEY (source_record_id, change_ordinal)
                REFERENCES fi.usn_object_change
                (source_record_id, change_ordinal)
        )`,
		`INSERT INTO fi.ntfs_object VALUES (7), (8)`,
	}

	for _, statement := range ddl {
		if _, err := conn.Exec(ctx, statement); err != nil {
			t.Fatalf("setup: %v", err)
		}
	}

	makeRow := func(parent int64, ordinal int) []any {
		return []any{
			parent, ordinal, 3, 0,
			"18446744073709551615",
			time.Date(2026, 10, 18, 18, 0, 0, 0, time.UTC),
			int64(4294967295), int64(1),
			int64(2), int64(32),
			[]byte{0x41, 0x00},
			int64(7), int64(8),
		}
	}

	reasons := []string{"FILE_CREATE", "CLOSE"}

	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())

	parents := make([][]any, 0, 350)
	for i := 0; i < 350; i++ {
		parents = append(parents, []any{int64(1000 + i)})
	}

	count, err := tx.CopyFrom(
		ctx,
		pgx.Identifier{"fi", "usn_object_observation"},
		[]string{"source_record_id"},
		pgx.CopyFromRows(parents),
	)
	if err != nil || count != 350 {
		t.Fatalf("parent COPY: %d %v", count, err)
	}

	state := newUSNChangeCopyState()

	for i := 0; i < 350; i++ {
		for ordinal := 1; ordinal <= 3; ordinal++ {
			if err := state.add(
				ctx, tx, makeRow(int64(1000+i), ordinal), reasons,
			); err != nil {
				t.Fatalf("change COPY: %v", err)
			}
		}
	}

	if state.changeRows != 1024 ||
		state.reasonRows != 2048 ||
		state.changeCalls != 1 ||
		state.reasonCalls != 1 ||
		len(state.changes.rows) != 26 ||
		len(state.reasons.rows) != 52 {
		t.Fatalf("incorrect boundary state: %+v", state)
	}

	if err := state.flushAll(ctx, tx); err != nil {
		t.Fatalf("final flush: %v", err)
	}

	if state.changeRows != 1050 ||
		state.reasonRows != 2100 ||
		state.changeCalls != 2 ||
		state.reasonCalls != 2 ||
		len(state.changes.rows) != 0 ||
		len(state.reasons.rows) != 0 {
		t.Fatalf("incorrect final state: %+v", state)
	}

	var changes, parentCount, precise, names int64
	err = tx.QueryRow(ctx, `
SELECT
    count(*),
    count(DISTINCT source_record_id),
    count(*) FILTER (
        WHERE usn = 18446744073709551615::numeric
          AND reason_raw = 4294967295
          AND file_name_utf16le = decode('4100','hex')
          AND file_ntfs_object_id = 7
          AND parent_ntfs_object_id = 8
    ),
    (SELECT count(*) FROM fi.usn_object_change_reason)
FROM fi.usn_object_change
`).Scan(&changes, &parentCount, &precise, &names)
	if err != nil {
		t.Fatal(err)
	}
	if changes != 1050 || parentCount != 350 ||
		precise != 1050 || names != 2100 {
		t.Fatalf(
			"incorrect relational values: %d %d %d %d",
			changes, parentCount, precise, names,
		)
	}

	var reasonOne, reasonTwo int64
	err = tx.QueryRow(ctx, `
SELECT
    count(*) FILTER (
        WHERE reason_ordinal = 1 AND reason_name = 'FILE_CREATE'
    ),
    count(*) FILTER (
        WHERE reason_ordinal = 2 AND reason_name = 'CLOSE'
    )
FROM fi.usn_object_change_reason
`).Scan(&reasonOne, &reasonTwo)
	if err != nil {
		t.Fatal(err)
	}
	if reasonOne != 1050 || reasonTwo != 1050 {
		t.Fatalf("incorrect reason ordinals: %d %d", reasonOne, reasonTwo)
	}

	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	checkEmpty := func() {
		t.Helper()
		var n int64
		err := conn.QueryRow(ctx, `
SELECT
    (SELECT count(*) FROM fi.usn_object_observation) +
    (SELECT count(*) FROM fi.usn_object_change) +
    (SELECT count(*) FROM fi.usn_object_change_reason)
`).Scan(&n)
		if err != nil || n != 0 {
			t.Fatalf("rollback left rows: %d %v", n, err)
		}
	}
	checkEmpty()

	// Duplicate change key after a successful COPY.
	dupTx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer dupTx.Rollback(context.Background())

	if _, err := dupTx.Exec(ctx,
		`INSERT INTO fi.usn_object_observation VALUES (9000)`,
	); err != nil {
		t.Fatal(err)
	}

	dup := newUSNChangeCopyState()
	for i := 1; i <= 1024; i++ {
		if err := dup.add(ctx, dupTx, makeRow(9000, i), reasons); err != nil {
			t.Fatal(err)
		}
	}
	if dup.changeRows != 1024 || dup.reasonRows != 2048 {
		t.Fatal("initial duplicate-test COPY incomplete")
	}
	if err := dup.add(ctx, dupTx, makeRow(9000, 1), reasons); err != nil {
		t.Fatal(err)
	}
	if err := dup.flushAll(ctx, dupTx); err == nil {
		t.Fatal("duplicate key unexpectedly accepted")
	}
	if err := dupTx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	checkEmpty()

	// Missing observation parent must reject the COPY.
	fkTx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer fkTx.Rollback(context.Background())

	fk := newUSNChangeCopyState()
	if err := fk.add(ctx, fkTx, makeRow(99999, 1), reasons); err != nil {
		t.Fatal(err)
	}
	if err := fk.flushAll(ctx, fkTx); err == nil {
		t.Fatal("missing parent unexpectedly accepted")
	}
	if err := fkTx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	checkEmpty()

	// A bad reason reference must roll back its valid change too.
	reasonTx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer reasonTx.Rollback(context.Background())

	if _, err := reasonTx.Exec(ctx,
		`INSERT INTO fi.usn_object_observation VALUES (9100)`,
	); err != nil {
		t.Fatal(err)
	}

	badReason := newUSNChangeCopyState()
	if err := badReason.add(
		ctx, reasonTx, makeRow(9100, 1), reasons,
	); err != nil {
		t.Fatal(err)
	}
	badReason.reasons.rows = append(
		badReason.reasons.rows,
		[]any{int64(9100), 999, 1, "INVALID_REFERENCE"},
	)

	if err := badReason.flushAll(ctx, reasonTx); err == nil {
		t.Fatal("invalid reason reference unexpectedly accepted")
	}
	if err := reasonTx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	checkEmpty()

	t.Log("PASS: 350 parents, 1024+26 changes, 2048+52 reasons")
	t.Log("PASS: uint64 numeric, attributes, UTF16 bytes, identities")
	t.Log("PASS: reason ordinals, duplicate, FK, reason FK, rollback")
}
