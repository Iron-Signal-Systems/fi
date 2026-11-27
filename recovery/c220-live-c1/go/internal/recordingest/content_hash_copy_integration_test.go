//go:build fi_hash_copy_integration

package recordingest

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/jackc/pgx/v5"
)

func TestContentHashCopyPostgreSQL(t *testing.T) {
	ctx := context.Background()
	dsn := os.Getenv("FI_HASH_COPY_TEST_DSN")
	if dsn == "" {
		t.Fatal("isolated PostgreSQL DSN required")
	}

	db, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close(ctx)

	// Reproduce the content-hash table's relevant live constraints.
	ddl := []string{
		`CREATE SCHEMA fi`,
		`CREATE TABLE fi.file_observation (
            source_record_id bigint PRIMARY KEY
        )`,
		`CREATE TABLE fi.content_hash_observation (
            source_record_id bigint PRIMARY KEY
                REFERENCES fi.file_observation(source_record_id),
            state text NOT NULL,
            bytes_hashed numeric(20,0),
            md5 bytea,
            sha1 bytea,
            sha256 bytea,
            reason_code text,
            detail text,
            CHECK (bytes_hashed IS NULL OR bytes_hashed >= 0),
            CHECK (md5 IS NULL OR octet_length(md5) = 16),
            CHECK (sha1 IS NULL OR octet_length(sha1) = 20),
            CHECK (sha256 IS NULL OR octet_length(sha256) = 32),
            CHECK (state IN ('Present', 'Error', 'NotApplicable')),
            CHECK (
                (state = 'Present'
                  AND bytes_hashed IS NOT NULL
                  AND md5 IS NOT NULL
                  AND sha1 IS NOT NULL
                  AND sha256 IS NOT NULL
                  AND reason_code IS NULL
                  AND detail IS NULL)
                OR
                (state = 'Error'
                  AND bytes_hashed IS NULL
                  AND md5 IS NULL
                  AND sha1 IS NULL
                  AND sha256 IS NULL
                  AND reason_code IS NOT NULL)
                OR
                (state = 'NotApplicable'
                  AND bytes_hashed IS NULL
                  AND md5 IS NULL
                  AND sha1 IS NULL
                  AND sha256 IS NULL
                  AND reason_code IS NULL
                  AND detail IS NULL)
            )
        )`,
		`CREATE INDEX content_hash_md5_idx
            ON fi.content_hash_observation (md5)
            WHERE md5 IS NOT NULL`,
		`CREATE INDEX content_hash_sha256_idx
            ON fi.content_hash_observation (sha256)
            WHERE sha256 IS NOT NULL`,
	}

	for _, sql := range ddl {
		if _, err := db.Exec(ctx, sql); err != nil {
			t.Fatalf("schema setup: %v", err)
		}
	}

	newCopyContext := func() (
		context.Context, *contentHashCopyState,
	) {
		state := newContentHashCopyState()
		c := context.WithValue(
			ctx, contentHashCopyContextKey{}, state,
		)
		return c, state
	}

	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())

	copyCtx, state := newCopyContext()

	// Cross the 1024-row batch boundary.
	for i := int64(1); i <= 1025; i++ {
		if _, err := tx.Exec(ctx, `
INSERT INTO fi.file_observation(source_record_id)
VALUES ($1)
`, i); err != nil {
			t.Fatal(err)
		}

		observation := records.ContentHashObservation{
			State:       records.ContentHashPresent,
			BytesHashed: "18446744073709551615",
			MD5:         strings.Repeat("a", 32),
			SHA1:        strings.Repeat("b", 40),
			SHA256:      strings.Repeat("c", 64),
		}

		if i == 2 {
			observation = records.ContentHashObservation{
				State:      records.ContentHashError,
				ReasonCode: "ReadError",
				Detail:     "simulated file read error",
			}
		}

		if i == 3 {
			observation = records.ContentHashObservation{
				State: records.ContentHashNotApplicable,
			}
		}

		if err := projectContentHashes(
			copyCtx, tx, i, observation,
		); err != nil {
			t.Fatalf("project record %d: %v", i, err)
		}
	}

	if state.copied != 1024 || state.calls != 1 {
		t.Fatalf(
			"batch boundary: copied=%d calls=%d",
			state.copied, state.calls,
		)
	}

	if err := state.flush(copyCtx, tx); err != nil {
		t.Fatalf("final COPY flush: %v", err)
	}

	if state.copied != 1025 || state.calls != 2 {
		t.Fatalf(
			"final COPY: copied=%d calls=%d",
			state.copied, state.calls,
		)
	}

	var count, errorRows, naRows int64
	var numeric, md5Hex, sha1Hex, sha256Hex string

	err = tx.QueryRow(ctx, `
SELECT
    (SELECT count(*) FROM fi.content_hash_observation),
    (SELECT count(*) FROM fi.content_hash_observation
        WHERE source_record_id = 2
          AND state = 'Error'
          AND bytes_hashed IS NULL
          AND reason_code = 'ReadError'
          AND detail = 'simulated file read error'),
    (SELECT count(*) FROM fi.content_hash_observation
        WHERE source_record_id = 3
          AND state = 'NotApplicable'
          AND bytes_hashed IS NULL
          AND reason_code IS NULL
          AND detail IS NULL)
`).Scan(&count, &errorRows, &naRows)
	if err != nil {
		t.Fatal(err)
	}

	if count != 1025 || errorRows != 1 || naRows != 1 {
		t.Fatalf(
			"row coverage: total=%d error=%d na=%d",
			count, errorRows, naRows,
		)
	}

	err = tx.QueryRow(ctx, `
SELECT bytes_hashed::text,
       encode(md5, 'hex'),
       encode(sha1, 'hex'),
       encode(sha256, 'hex')
FROM fi.content_hash_observation
WHERE source_record_id = 1
`).Scan(&numeric, &md5Hex, &sha1Hex, &sha256Hex)
	if err != nil {
		t.Fatal(err)
	}

	if numeric != "18446744073709551615" ||
		md5Hex != strings.Repeat("a", 32) ||
		sha1Hex != strings.Repeat("b", 40) ||
		sha256Hex != strings.Repeat("c", 64) {
		t.Fatalf("hash or numeric round-trip mismatch")
	}

	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	t.Log("PASS: 1025 rows in two COPY calls")
	t.Log("PASS: exact 20-digit numeric and digest bytes")
	t.Log("PASS: Present, Error, and NotApplicable states")

	// Deliberately violate the state-shape constraint.
	badTx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer badTx.Rollback(context.Background())

	if _, err := badTx.Exec(ctx, `
INSERT INTO fi.file_observation(source_record_id)
VALUES (2001)
`); err != nil {
		t.Fatal(err)
	}

	badCtx, badState := newCopyContext()

	// Error requires a non-NULL reason_code.
	bad := records.ContentHashObservation{
		State: records.ContentHashError,
	}

	if err := projectContentHashes(
		badCtx, badTx, 2001, bad,
	); err != nil {
		t.Fatal(err)
	}

	if err := badState.flush(badCtx, badTx); err == nil {
		t.Fatal("invalid hash shape accepted by PostgreSQL")
	}

	if err := badTx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	var parentCount, hashCount int64
	err = db.QueryRow(ctx, `
SELECT
    (SELECT count(*) FROM fi.file_observation
     WHERE source_record_id = 2001),
    (SELECT count(*) FROM fi.content_hash_observation
     WHERE source_record_id = 2001)
`).Scan(&parentCount, &hashCount)

	if err != nil || parentCount != 0 || hashCount != 0 {
		t.Fatalf(
			"failed COPY persisted rows: parent=%d hash=%d err=%v",
			parentCount, hashCount, err,
		)
	}

	// The hash table must reject a nonexistent file-observation parent.
	fkTx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer fkTx.Rollback(context.Background())

	fkCtx, fkState := newCopyContext()

	if err := projectContentHashes(
		fkCtx, fkTx, 9001,
		records.ContentHashObservation{
			State: records.ContentHashNotApplicable,
		},
	); err != nil {
		t.Fatal(err)
	}

	if err := fkState.flush(fkCtx, fkTx); err == nil {
		t.Fatal("missing file-observation parent accepted")
	}

	if err := fkTx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	// A duplicate source_record_id must still be rejected.
	dupTx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer dupTx.Rollback(context.Background())

	dupCtx, dupState := newCopyContext()

	if err := projectContentHashes(
		dupCtx, dupTx, 1,
		records.ContentHashObservation{
			State: records.ContentHashNotApplicable,
		},
	); err != nil {
		t.Fatal(err)
	}

	if err := dupState.flush(dupCtx, dupTx); err == nil {
		t.Fatal("duplicate content-hash identity accepted")
	}

	if err := dupTx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	t.Log("PASS: invalid state-shape rejected")
	t.Log("PASS: missing parent rejected")
	t.Log("PASS: duplicate primary key rejected")
	t.Log("PASS: failed transactions rolled back")
}
