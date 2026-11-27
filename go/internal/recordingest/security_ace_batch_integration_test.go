//go:build fi_security_ace_batch_integration

package recordingest

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/jackc/pgx/v5"
)

func TestSecurityACEBatchPostgreSQL(t *testing.T) {
	dsn := os.Getenv("FI_ACE_TEST_DSN")
	expected := os.Getenv("FI_ACE_TEST_DATA")
	if dsn == "" || expected == "" {
		t.Fatal("isolated PostgreSQL configuration required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())

	var directory, listen string
	if err := conn.QueryRow(ctx, "SHOW data_directory").Scan(&directory); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRow(ctx, "SHOW listen_addresses").Scan(&listen); err != nil {
		t.Fatal(err)
	}
	if filepath.Clean(directory) != filepath.Clean(expected) || listen != "" {
		t.Fatalf("STOP: unexpected PostgreSQL instance: %q %q", directory, listen)
	}

	var schemaAbsent bool
	if err := conn.QueryRow(ctx,
		"SELECT to_regnamespace('fi') IS NULL",
	).Scan(&schemaAbsent); err != nil {
		t.Fatal(err)
	}
	if !schemaAbsent {
		t.Fatal("STOP: FI schema already exists")
	}

	for _, statement := range []string{
		`CREATE SCHEMA fi`,
		`CREATE TABLE fi.security_observation (
source_record_id bigint PRIMARY KEY
)`,
		`CREATE TABLE fi.sacl_observation (
source_record_id bigint PRIMARY KEY
)`,
	} {
		if _, err := conn.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}

	// Same ACE column types, checks and parent FKs as FI's schema.
	for _, table := range []struct{ name, parent string }{
		{"security_ace", "security_observation"},
		{"sacl_ace", "sacl_observation"},
	} {
		ddl := fmt.Sprintf(`
CREATE TABLE fi.%s (
source_record_id bigint NOT NULL
REFERENCES fi.%s(source_record_id),
ace_ordinal integer NOT NULL CHECK (ace_ordinal >= 0),
ace_type integer NOT NULL,
type_name text NOT NULL,
flags integer NOT NULL,
ace_size integer NOT NULL CHECK (ace_size > 0),
raw_ace bytea NOT NULL,
access_mask bigint,
object_flags bigint,
object_type_guid uuid,
inherited_object_type_guid uuid,
sid text,
PRIMARY KEY (source_record_id, ace_ordinal)
)`, table.name, table.parent)

		if _, err := conn.Exec(ctx, ddl); err != nil {
			t.Fatal(err)
		}
	}

	makeACE := func(index int) records.ACEObservation {
		return records.ACEObservation{
			Index:    fmt.Sprint(index),
			Type:     "0",
			TypeName: "AccessAllowed",
			Flags:    "0",
			Size:     "4",
			RawBase64URL: base64.RawURLEncoding.EncodeToString(
				[]byte{0, 0, 4, 0},
			),
			Mask:        "31",
			ObjectFlags: "1",
			SID:         "S-1-5-18",
		}
	}

	// Success path: cross the 128-ACE batch boundary.
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())

	if _, err := tx.Exec(ctx,
		`INSERT INTO fi.security_observation VALUES (11)`,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO fi.sacl_observation VALUES (22)`,
	); err != nil {
		t.Fatal(err)
	}

	dacl := make([]records.ACEObservation, 130)
	for i := range dacl {
		dacl[i] = makeACE(i)
	}
	dacl[0].ObjectTypeGUID = "00112233-4455-6677-8899-aabbccddeeff"

	sacl := []records.ACEObservation{
		makeACE(0), makeACE(1), makeACE(2),
	}

	if err := projectSecurityACEs(ctx, tx, "fi.security_ace", 11, dacl); err != nil {
		t.Fatalf("DACL batch: %v", err)
	}
	if err := projectSecurityACEs(ctx, tx, "fi.sacl_ace", 22, sacl); err != nil {
		t.Fatalf("SACL batch: %v", err)
	}

	var daclCount, saclCount, goodRows, uuidCount int64

	err = tx.QueryRow(ctx, `
SELECT
 (SELECT count(*) FROM fi.security_ace),
 (SELECT count(*) FROM fi.sacl_ace),
 (SELECT count(*) FROM fi.security_ace
  WHERE ace_size=4
    AND octet_length(raw_ace)=4
    AND access_mask=31
    AND object_flags=1
    AND sid='S-1-5-18'),
 (SELECT count(*) FROM fi.security_ace
  WHERE object_type_guid =
    '00112233-4455-6677-8899-aabbccddeeff'::uuid)
`).Scan(&daclCount, &saclCount, &goodRows, &uuidCount)
	if err != nil {
		t.Fatal(err)
	}

	if daclCount != 130 || saclCount != 3 ||
		goodRows != 130 || uuidCount != 1 {
		t.Fatalf("incorrect ACE projection: %d %d %d %d",
			daclCount, saclCount, goodRows, uuidCount)
	}

	var minOrdinal, maxOrdinal, distinctOrdinals int64
	err = tx.QueryRow(ctx, `
SELECT min(ace_ordinal), max(ace_ordinal),
       count(DISTINCT ace_ordinal)
FROM fi.security_ace
`).Scan(&minOrdinal, &maxOrdinal, &distinctOrdinals)
	if err != nil {
		t.Fatal(err)
	}
	if minOrdinal != 0 || maxOrdinal != 129 || distinctOrdinals != 130 {
		t.Fatal("ACE ordinals were not preserved")
	}

	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	var remaining int64
	if err := conn.QueryRow(ctx, `
SELECT
 (SELECT count(*) FROM fi.security_ace) +
 (SELECT count(*) FROM fi.sacl_ace) +
 (SELECT count(*) FROM fi.security_observation) +
 (SELECT count(*) FROM fi.sacl_observation)
`).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatal("successful batch rollback left rows")
	}

	// Failure path: duplicate primary key must reject the batch.
	failTx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer failTx.Rollback(context.Background())

	if _, err := failTx.Exec(ctx,
		`INSERT INTO fi.security_observation VALUES (33)`,
	); err != nil {
		t.Fatal(err)
	}

	duplicate := []records.ACEObservation{
		makeACE(0), makeACE(0),
	}
	if err := projectSecurityACEs(
		ctx, failTx, "fi.security_ace", 33, duplicate,
	); err == nil {
		t.Fatal("duplicate ACE ordinal unexpectedly accepted")
	}

	if err := failTx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	// Failure path: foreign-key relationship must be enforced.
	fkTx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer fkTx.Rollback(context.Background())

	if err := projectSecurityACEs(
		ctx, fkTx, "fi.sacl_ace", 999, sacl,
	); err == nil {
		t.Fatal("ACE without parent unexpectedly accepted")
	}
	if err := fkTx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	if err := conn.QueryRow(ctx, `
SELECT
 (SELECT count(*) FROM fi.security_ace) +
 (SELECT count(*) FROM fi.sacl_ace) +
 (SELECT count(*) FROM fi.security_observation) +
 (SELECT count(*) FROM fi.sacl_observation)
`).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatal("failed batch rollback left rows")
	}

	t.Log("BEGIN: cross-observation ACE COPY")

	copyTx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer copyTx.Rollback(context.Background())

	daclParents := make([][]any, 0, 350)
	saclParents := make([][]any, 0, 350)

	for i := 0; i < 350; i++ {
		daclParents = append(daclParents, []any{int64(1001 + i)})
		saclParents = append(saclParents, []any{int64(2001 + i)})
	}

	for _, parent := range []struct {
		table string
		rows  [][]any
	}{
		{"security_observation", daclParents},
		{"sacl_observation", saclParents},
	} {
		count, err := copyTx.CopyFrom(
			ctx,
			pgx.Identifier{"fi", parent.table},
			[]string{"source_record_id"},
			pgx.CopyFromRows(parent.rows),
		)
		if err != nil || count != 350 {
			t.Fatalf("create COPY parents %s: %d %v",
				parent.table, count, err)
		}
	}

	copyState := newACECopyState()
	copyCtx := context.WithValue(ctx, aceCopyContextKey{}, copyState)

	for i := 0; i < 350; i++ {
		dacl := []records.ACEObservation{
			makeACE(0), makeACE(1), makeACE(2),
		}
		dacl[0].ObjectTypeGUID =
			"00112233-4455-6677-8899-aabbccddeeff"

		sacl := []records.ACEObservation{
			makeACE(0), makeACE(1), makeACE(2),
		}
		sacl[0].InheritedObjectTypeGUID =
			"11223344-5566-7788-99aa-bbccddeeff00"

		if err := projectSecurityACEs(
			copyCtx, copyTx, "fi.security_ace",
			int64(1001+i), dacl,
		); err != nil {
			t.Fatalf("cross-observation DACL: %v", err)
		}

		if err := projectSecurityACEs(
			copyCtx, copyTx, "fi.sacl_ace",
			int64(2001+i), sacl,
		); err != nil {
			t.Fatalf("cross-observation SACL: %v", err)
		}
	}

	if copyState.calls != 2 ||
		copyState.daclRows != 1024 ||
		copyState.saclRows != 1024 ||
		len(copyState.dacl.rows) != 26 ||
		len(copyState.sacl.rows) != 26 {
		t.Fatalf("incorrect intermediate COPY state: %+v", copyState)
	}

	if err := copyState.flushAll(ctx, copyTx); err != nil {
		t.Fatalf("final ACE COPY flush: %v", err)
	}

	if copyState.calls != 4 ||
		copyState.daclRows != 1050 ||
		copyState.saclRows != 1050 ||
		len(copyState.dacl.rows) != 0 ||
		len(copyState.sacl.rows) != 0 {
		t.Fatalf("incorrect final COPY state: %+v", copyState)
	}

	var copiedDACL, copiedSACL, daclUUID, saclUUID int64

	err = copyTx.QueryRow(ctx, `
SELECT
    (SELECT count(*) FROM fi.security_ace),
    (SELECT count(*) FROM fi.sacl_ace),
    (SELECT count(*) FROM fi.security_ace
     WHERE object_type_guid =
       '00112233-4455-6677-8899-aabbccddeeff'::uuid),
    (SELECT count(*) FROM fi.sacl_ace
     WHERE inherited_object_type_guid =
       '11223344-5566-7788-99aa-bbccddeeff00'::uuid)
`).Scan(&copiedDACL, &copiedSACL, &daclUUID, &saclUUID)

	if err != nil {
		t.Fatal(err)
	}
	if copiedDACL != 1050 || copiedSACL != 1050 ||
		daclUUID != 350 || saclUUID != 350 {
		t.Fatalf("incorrect COPY values: %d %d %d %d",
			copiedDACL, copiedSACL, daclUUID, saclUUID)
	}

	if err := copyTx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	// Duplicate key in a later COPY must reject the transaction.
	dupTx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer dupTx.Rollback(context.Background())

	if _, err := dupTx.Exec(ctx,
		"INSERT INTO fi.security_observation VALUES (9000)",
	); err != nil {
		t.Fatal(err)
	}

	dupState := newACECopyState()
	dupCtx := context.WithValue(ctx, aceCopyContextKey{}, dupState)

	for i := 0; i < 1024; i++ {
		if err := projectSecurityACEs(
			dupCtx, dupTx, "fi.security_ace", 9000,
			[]records.ACEObservation{makeACE(i)},
		); err != nil {
			t.Fatalf("prepare duplicate test: %v", err)
		}
	}

	if dupState.daclRows != 1024 {
		t.Fatal("first duplicate-test COPY did not flush")
	}

	if err := projectSecurityACEs(
		dupCtx, dupTx, "fi.security_ace", 9000,
		[]records.ACEObservation{makeACE(0)},
	); err != nil {
		t.Fatal(err)
	}

	if err := dupState.flushAll(ctx, dupTx); err == nil {
		t.Fatal("duplicate ACE COPY unexpectedly accepted")
	}

	if err := dupTx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	// Missing parent must reject COPY.
	fkCopyTx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer fkCopyTx.Rollback(context.Background())

	fkState := newACECopyState()
	fkCtx := context.WithValue(ctx, aceCopyContextKey{}, fkState)

	if err := projectSecurityACEs(
		fkCtx, fkCopyTx, "fi.sacl_ace", 99999,
		[]records.ACEObservation{makeACE(0)},
	); err != nil {
		t.Fatal(err)
	}

	if err := fkState.flushAll(ctx, fkCopyTx); err == nil {
		t.Fatal("missing-parent ACE COPY unexpectedly accepted")
	}

	if err := fkCopyTx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	if err := conn.QueryRow(ctx, `
SELECT
 (SELECT count(*) FROM fi.security_ace) +
 (SELECT count(*) FROM fi.sacl_ace) +
 (SELECT count(*) FROM fi.security_observation) +
 (SELECT count(*) FROM fi.sacl_observation)
`).Scan(&remaining); err != nil {
		t.Fatal(err)
	}

	if remaining != 0 {
		t.Fatalf("COPY rollback left %d rows", remaining)
	}

	t.Log("PASS: 350 parents/table, 1024+26 COPY, UUID, duplicate, FK, rollback")

	t.Log("PASS: 128 boundary, DACL, SACL, UUID, ordinals, FK, rejection, rollback")
}
