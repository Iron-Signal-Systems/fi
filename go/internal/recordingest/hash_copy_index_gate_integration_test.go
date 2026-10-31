//go:build freebsd && fi_hash_copy_index_gate_integration

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

// Only this new schema is ever created/dropped. The production FI schema and
// existing development/isolated fixtures are read only for this test.
const (
	hashGateSchema   = "fi_hash_copy_gate_20261030"
	hashGatePort     = uint16(55442)
	hashGateMaxRows  = 1000000
	hashGateCopyRows = 1024 // Baseline; optional test-only override is bounded.
)

var hashGateColumns = []string{
	"source_record_id", "state", "bytes_hashed", "md5", "sha1",
	"sha256", "reason_code", "detail",
}

// hashGateDigests precomputes exact hash bytes outside the timed COPY regions.
// It occupies 68 bytes/row, not N dynamic Go record objects. The final row
// intentionally duplicates the first digest to test non-unique equality queries.
// All source IDs remain distinct.
type hashGateDigests struct {
	rows        int
	md5Bytes    []byte
	sha1Bytes   []byte
	sha256Bytes []byte
}

func newHashGateDigests(rows int) *hashGateDigests {
	d := &hashGateDigests{
		rows:        rows,
		md5Bytes:    make([]byte, rows*16),
		sha1Bytes:   make([]byte, rows*20),
		sha256Bytes: make([]byte, rows*32),
	}
	var key [8]byte
	for i := 0; i < rows-1; i++ {
		binary.LittleEndian.PutUint64(key[:], uint64(i+1))
		m := md5.Sum(key[:])
		a := sha1.Sum(key[:])
		b := sha256.Sum256(key[:])
		copy(d.md5Bytes[i*16:(i+1)*16], m[:])
		copy(d.sha1Bytes[i*20:(i+1)*20], a[:])
		copy(d.sha256Bytes[i*32:(i+1)*32], b[:])
	}
	// Copy row zero into final row to confirm duplicate digests are accepted.
	copy(d.md5Bytes[(rows-1)*16:], d.md5Bytes[:16])
	copy(d.sha1Bytes[(rows-1)*20:], d.sha1Bytes[:20])
	copy(d.sha256Bytes[(rows-1)*32:], d.sha256Bytes[:32])
	return d
}

func (d *hashGateDigests) values(i int, numeric16 pgtype.Numeric) []any {
	return []any{
		int64(i + 1), "Present", numeric16,
		d.md5Bytes[i*16 : (i+1)*16],
		d.sha1Bytes[i*20 : (i+1)*20],
		d.sha256Bytes[i*32 : (i+1)*32],
		nil, nil,
	}
}

type hashGateResult struct {
	round      int
	variant    string
	calls      int
	elapsed    time.Duration
	walBytes   int64
	indexBytes int64
}

func TestFIHashCopyIndexGate(t *testing.T) {
	root := "/home/jwood/fi-prefetch-20261030.CTwtoA"
	expectedData := filepath.Join(root, "data")
	expectedSocket := filepath.Join(root, "socket")
	if os.Getenv("FI_HASH_GATE_ALLOW_ISOLATED_WRITES") != "1" ||
		os.Getenv("FI_HASH_GATE_DATA") != expectedData ||
		os.Getenv("FI_HASH_GATE_SOCKET") != expectedSocket {
		t.Fatal("STOP: isolated hash gate requires exact fixture identity and explicit opt-in")
	}
	version, err := os.ReadFile(filepath.Join(expectedData, "PG_VERSION"))
	if err != nil || strings.TrimSpace(string(version)) != "18" {
		t.Fatal("STOP: expected isolated PostgreSQL 18 marker")
	}
	rows := 250000
	if v := os.Getenv("FI_HASH_GATE_ROWS"); v != "" {
		rows, err = strconv.Atoi(v)
		if err != nil || rows < 1024 || rows > hashGateMaxRows {
			t.Fatal("FI_HASH_GATE_ROWS must be 1024..1000000")
		}
	}
	// Test-only batch-size variant; production content hash bounds are unchanged.
	copyRows := hashGateCopyRows
	if raw := os.Getenv("FI_HASH_GATE_COPY_ROWS"); raw != "" {
		copyRows, err = strconv.Atoi(raw)
		if err != nil || (copyRows != 1024 && copyRows != 4096) {
			t.Fatal("FI_HASH_GATE_COPY_ROWS must equal 1024 or 4096")
		}
	}
	// Run a bounded fixture even on errors; no live database or network path.
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Minute)
	defer cancel()
	adminDSN := fmt.Sprintf("host=%s port=%d user=jwood dbname=fi sslmode=disable connect_timeout=3", expectedSocket, hashGatePort)
	runtimeDSN := fmt.Sprintf("host=%s port=%d user=fi_ingest dbname=fi sslmode=disable connect_timeout=3", expectedSocket, hashGatePort)
	admin, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close(context.Background()) })
	runtime, err := pgx.Connect(ctx, runtimeDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close(context.Background()) })
	hashGateVerifyIdentity(t, ctx, admin, expectedData, expectedSocket, "jwood")
	hashGateVerifyIdentity(t, ctx, runtime, expectedData, expectedSocket, "fi_ingest")

	var present bool
	if err := admin.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname=$1)`, hashGateSchema,
	).Scan(&present); err != nil {
		t.Fatal(err)
	}
	if present {
		t.Fatal("STOP: benchmark schema already exists; do not overwrite earlier evidence")
	}
	if _, err := admin.Exec(ctx, `CREATE SCHEMA fi_hash_copy_gate_20261030`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanCtx, stop := context.WithTimeout(context.Background(), 2*time.Minute)
		defer stop()
		_, cleanupErr := admin.Exec(cleanCtx, `DROP SCHEMA fi_hash_copy_gate_20261030 CASCADE`)
		if cleanupErr != nil {
			t.Errorf("isolated benchmark cleanup failed: %v", cleanupErr)
		}
	})
	hashGateBuildSchema(t, ctx, admin, rows)
	data := newHashGateDigests(rows)
	t.Logf("FI HASH COPY GATE rows=%d rows_per_copy=%d; precomputed hash bytes=%d; FK enforced; variants=btree,hash,pk_only", rows, copyRows, rows*68)
	results := make([]hashGateResult, 0, 5)

	for round, order := range [][]string{{"btree", "hash"}, {"hash", "btree"}} {
		for _, variant := range order {
			hashGateTruncate(t, ctx, admin, variant)
			hashGateRollbackTest(t, ctx, runtime, variant, data)
			result := hashGateCopy(t, ctx, runtime, variant, data, copyRows)
			result.round = round + 1
			hashGateCheck(t, ctx, admin, runtime, variant, data)
			hashGateNullStateCheck(t, ctx, admin, runtime, variant, data.rows)
			result.indexBytes = hashGateIndexBytes(t, ctx, admin, variant)
			results = append(results, result)
			t.Logf("FI HASH COPY RESULT round=%d design=%s rows=%d calls=%d elapsed=%s rate=%.1f_rows_per_s wal_delta=%d index_bytes=%d",
				result.round, result.variant, rows, result.calls, result.elapsed.Round(time.Millisecond),
				float64(rows)/result.elapsed.Seconds(), result.walBytes, result.indexBytes)
		}
	}
	// PK-only identifies the baseline cost of FK/check constraints + primary key.
	hashGateTruncate(t, ctx, admin, "pk_only")
	hashGateRollbackTest(t, ctx, runtime, "pk_only", data)
	pk := hashGateCopy(t, ctx, runtime, "pk_only", data, copyRows)
	pk.round = 1
	hashGateCheck(t, ctx, admin, runtime, "pk_only", data)
	hashGateNullStateCheck(t, ctx, admin, runtime, "pk_only", data.rows)
	pk.indexBytes = hashGateIndexBytes(t, ctx, admin, "pk_only")
	results = append(results, pk)
	t.Logf("FI HASH COPY RESULT round=1 design=pk_only rows=%d calls=%d elapsed=%s rate=%.1f_rows_per_s wal_delta=%d index_bytes=%d",
		rows, pk.calls, pk.elapsed.Round(time.Millisecond), float64(rows)/pk.elapsed.Seconds(), pk.walBytes, pk.indexBytes)
	for _, result := range results {
		t.Logf("FI HASH COPY SUMMARY round=%d design=%s rows=%d calls=%d seconds=%.4f wal_bytes=%d indexes_bytes=%d",
			result.round, result.variant, rows, result.calls, result.elapsed.Seconds(), result.walBytes, result.indexBytes)
	}
}

func hashGateVerifyIdentity(t *testing.T, ctx context.Context, conn *pgx.Conn, data, socket, role string) {
	t.Helper()
	cfg := conn.Config()
	if cfg.Host != socket || cfg.Port != hashGatePort || cfg.Database != "fi" || cfg.User != role {
		t.Fatalf("STOP: unsafe PostgreSQL connection config host=%q port=%d db=%q user=%q", cfg.Host, cfg.Port, cfg.Database, cfg.User)
	}
	var observedData, listen, db, user, port string
	if err := conn.QueryRow(ctx,
		`SELECT current_setting('data_directory'), current_setting('listen_addresses'), current_database(), current_user, current_setting('port')`,
	).Scan(&observedData, &listen, &db, &user, &port); err != nil {
		// fi_ingest is deliberately prohibited from reading data_directory.
		if role != "fi_ingest" {
			t.Fatalf("STOP: cannot verify PostgreSQL data_directory: %v", err)
		}
		if err := conn.QueryRow(ctx,
			`SELECT current_setting('listen_addresses'), current_database(), current_user, current_setting('port')`,
		).Scan(&listen, &db, &user, &port); err != nil {
			t.Fatal(err)
		}
	} else if observedData != data {
		t.Fatalf("STOP: PostgreSQL data_directory=%q expected=%q", observedData, data)
	}
	if listen != "" || db != "fi" || user != role || port != "55442" {
		t.Fatalf("STOP: unsafe PostgreSQL connection listen=%q db=%q user=%q port=%q", listen, db, user, port)
	}
}

func hashGateBuildSchema(t *testing.T, ctx context.Context, admin *pgx.Conn, rows int) {
	t.Helper()
	commands := []string{
		`CREATE TABLE fi_hash_copy_gate_20261030.parent (source_record_id bigint PRIMARY KEY)`,
		`CREATE TABLE fi_hash_copy_gate_20261030.btree (LIKE fi.content_hash_observation INCLUDING CONSTRAINTS)`,
		`CREATE TABLE fi_hash_copy_gate_20261030.hash (LIKE fi.content_hash_observation INCLUDING CONSTRAINTS)`,
		`CREATE TABLE fi_hash_copy_gate_20261030.pk_only (LIKE fi.content_hash_observation INCLUDING CONSTRAINTS)`,
		`ALTER TABLE fi_hash_copy_gate_20261030.btree ADD PRIMARY KEY (source_record_id)`,
		`ALTER TABLE fi_hash_copy_gate_20261030.hash ADD PRIMARY KEY (source_record_id)`,
		`ALTER TABLE fi_hash_copy_gate_20261030.pk_only ADD PRIMARY KEY (source_record_id)`,
		`ALTER TABLE fi_hash_copy_gate_20261030.btree ADD FOREIGN KEY (source_record_id) REFERENCES fi_hash_copy_gate_20261030.parent(source_record_id)`,
		`ALTER TABLE fi_hash_copy_gate_20261030.hash ADD FOREIGN KEY (source_record_id) REFERENCES fi_hash_copy_gate_20261030.parent(source_record_id)`,
		`ALTER TABLE fi_hash_copy_gate_20261030.pk_only ADD FOREIGN KEY (source_record_id) REFERENCES fi_hash_copy_gate_20261030.parent(source_record_id)`,
		`CREATE INDEX gate_btree_md5 ON fi_hash_copy_gate_20261030.btree USING btree (md5) WHERE md5 IS NOT NULL`,
		`CREATE INDEX gate_btree_sha256 ON fi_hash_copy_gate_20261030.btree USING btree (sha256) WHERE sha256 IS NOT NULL`,
		`CREATE INDEX gate_hash_md5 ON fi_hash_copy_gate_20261030.hash USING hash (md5) WHERE md5 IS NOT NULL`,
		`CREATE INDEX gate_hash_sha256 ON fi_hash_copy_gate_20261030.hash USING hash (sha256) WHERE sha256 IS NOT NULL`,
		`GRANT USAGE ON SCHEMA fi_hash_copy_gate_20261030 TO fi_ingest`,
		`GRANT SELECT ON fi_hash_copy_gate_20261030.parent TO fi_ingest`,
		`GRANT SELECT, INSERT ON fi_hash_copy_gate_20261030.btree, fi_hash_copy_gate_20261030.hash, fi_hash_copy_gate_20261030.pk_only TO fi_ingest`,
	}
	for _, sql := range commands {
		if _, err := admin.Exec(ctx, sql); err != nil {
			t.Fatalf("create isolated benchmark schema: %v; sql=%s", err, sql)
		}
	}
	tag, err := admin.Exec(ctx, `INSERT INTO fi_hash_copy_gate_20261030.parent SELECT g FROM generate_series(1, $1::integer + 2) AS g`, rows)
	if err != nil || tag.RowsAffected() != int64(rows+2) {
		t.Fatalf("create isolated parent rows: %v inserted=%d expected=%d", err, tag.RowsAffected(), rows+2)
	}
	if _, err := admin.Exec(ctx, `ANALYZE fi_hash_copy_gate_20261030.parent`); err != nil {
		t.Fatal(err)
	}
}

func hashGateTruncate(t *testing.T, ctx context.Context, admin *pgx.Conn, variant string) {
	t.Helper()
	sql := `TRUNCATE ` + pgx.Identifier{hashGateSchema, variant}.Sanitize()
	if _, err := admin.Exec(ctx, sql); err != nil {
		t.Fatalf("truncate isolated %s fixture: %v", variant, err)
	}
}

// This deliberately attempts one invalid parent from the FI-like hash table,
// and verifies PostgreSQL FK rejection and subsequent rollback. It takes place
// before, not inside, the measured COPY interval.
func hashGateRollbackTest(t *testing.T, ctx context.Context, conn *pgx.Conn, variant string, data *hashGateDigests) {
	t.Helper()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	numeric16 := pgtype.Numeric{Int: big.NewInt(16), Valid: true}
	rows := [][]any{data.values(0, numeric16), data.values(1, numeric16)}
	count, err := tx.CopyFrom(ctx, pgx.Identifier{hashGateSchema, variant}, hashGateColumns, pgx.CopyFromRows(rows))
	if err != nil || count != 2 {
		t.Fatalf("test rollback setup %s count=%d err=%v", variant, count, err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var remaining int64
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM `+pgx.Identifier{hashGateSchema, variant}.Sanitize()).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatalf("rollback failed for %s: count=%d err=%v", variant, remaining, err)
	}
	tx2, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx2.Rollback(context.Background())
	invalid := data.values(0, numeric16)
	invalid[0] = int64(data.rows + 3)
	_, err = tx2.CopyFrom(ctx, pgx.Identifier{hashGateSchema, variant}, hashGateColumns, pgx.CopyFromRows([][]any{invalid}))
	pgErr, ok := err.(*pgconn.PgError)
	if !ok || pgErr.Code != "23503" {
		t.Fatalf("FK violation not rejected for %s: %v", variant, err)
	}
	if err := tx2.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
}

func hashGateWal(t *testing.T, ctx context.Context, admin *pgx.Conn) int64 {
	t.Helper()
	var v int64
	if err := admin.QueryRow(ctx, `SELECT wal_bytes::bigint FROM pg_stat_wal`).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func hashGateCopy(t *testing.T, ctx context.Context, conn *pgx.Conn, variant string, data *hashGateDigests, copyRows int) hashGateResult {
	t.Helper()
	// Stats are a diagnostic only. Elapsed time, exact row counts and SQL
	// correctness are the acceptance facts; WAL counters can be asynchronous.
	walStart := hashGateWal(t, ctx, conn)
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	numeric16 := pgtype.Numeric{Int: big.NewInt(16), Valid: true}
	calls := 0
	started := time.Now()
	for offset := 0; offset < data.rows; offset += copyRows {
		n := copyRows
		if offset+n > data.rows {
			n = data.rows - offset
		}
		base := offset
		copied, copyErr := tx.CopyFrom(ctx,
			pgx.Identifier{hashGateSchema, variant}, hashGateColumns,
			pgx.CopyFromSlice(n, func(i int) ([]any, error) {
				return data.values(base+i, numeric16), nil
			}),
		)
		if copyErr != nil || copied != int64(n) {
			t.Fatalf("binary pgx.CopyFrom %s chunk=%d count=%d expected=%d err=%v", variant, calls, copied, n, copyErr)
		}
		calls++
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("COPY commit %s: %v", variant, err)
	}
	elapsed := time.Since(started)
	walEnd := hashGateWal(t, ctx, conn)
	return hashGateResult{variant: variant, calls: calls, elapsed: elapsed, walBytes: walEnd - walStart}
}

func hashGateCheck(t *testing.T, ctx context.Context, admin, runtime *pgx.Conn, variant string, data *hashGateDigests) {
	t.Helper()
	table := pgx.Identifier{hashGateSchema, variant}.Sanitize()
	var actual int64
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM `+table).Scan(&actual); err != nil || actual != int64(data.rows) {
		t.Fatalf("COPY count %s got=%d expected=%d err=%v", variant, actual, data.rows, err)
	}
	if _, err := admin.Exec(ctx, `ANALYZE `+table); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		field    string
		hash     []byte
		expected int64
	}{
		{"md5", data.md5Bytes[:16], 2}, {"sha256", data.sha256Bytes[:32], 2},
	} {
		sql := fmt.Sprintf(`SELECT count(*),min(source_record_id),max(source_record_id) FROM %s WHERE %s=$1`, table, test.field)
		var count, first, last int64
		if err := runtime.QueryRow(ctx, sql, test.hash).Scan(&count, &first, &last); err != nil || count != test.expected || first != 1 || last != int64(data.rows) {
			t.Fatalf("duplicate %s equality lookup %s count=%d first=%d last=%d err=%v", variant, test.field, count, first, last, err)
		}
		if variant != "pk_only" {
			planRows, err := runtime.Query(ctx, `EXPLAIN `+fmt.Sprintf(`SELECT source_record_id FROM %s WHERE %s=$1`, table, test.field), test.hash)
			if err != nil {
				t.Fatal(err)
			}
			var plan strings.Builder
			for planRows.Next() {
				var line string
				if err := planRows.Scan(&line); err != nil {
					planRows.Close()
					t.Fatal(err)
				}
				plan.WriteString(line)
				plan.WriteByte('\n')
			}
			if err := planRows.Err(); err != nil {
				planRows.Close()
				t.Fatal(err)
			}
			planRows.Close()
			expectedIndex := "gate_" + variant + "_" + test.field
			if !strings.Contains(plan.String(), expectedIndex) {
				t.Fatalf("index not used for %s %s equality: expected %s; plan=%s", variant, test.field, expectedIndex, plan.String())
			}
			t.Logf("FI HASH EQUALITY PLAN design=%s field=%s index=%s count=2", variant, test.field, expectedIndex)
		}
	}
}

func hashGateIndexBytes(t *testing.T, ctx context.Context, conn *pgx.Conn, variant string) int64 {
	t.Helper()
	var value int64
	if err := conn.QueryRow(ctx, `SELECT pg_indexes_size($1::regclass)::bigint`, hashGateSchema+"."+variant).Scan(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

// Check nullable partial-index behavior and the original FI three-state
// constraints outside the timed all-Present COPY workload. Runtime retains
// append-only privileges; no DELETE/TRUNCATE is granted to fi_ingest.
func hashGateNullStateCheck(t *testing.T, ctx context.Context, admin, runtime *pgx.Conn, variant string, count int) {
	t.Helper()
	table := pgx.Identifier{hashGateSchema, variant}
	tx, err := runtime.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	rows := [][]any{
		{int64(count + 1), "Error", nil, nil, nil, nil, "AccessDenied", nil},
		{int64(count + 2), "NotApplicable", nil, nil, nil, nil, nil, nil},
	}
	inserted, err := tx.CopyFrom(ctx, table, hashGateColumns, pgx.CopyFromRows(rows))
	if err != nil || inserted != 2 {
		t.Fatalf("partial-index nullable states %s inserted=%d err=%v", variant, inserted, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var got int64
	sql := fmt.Sprintf(`SELECT count(*) FROM %s WHERE md5 IS NULL AND sha256 IS NULL`, table.Sanitize())
	if err := admin.QueryRow(ctx, sql).Scan(&got); err != nil || got != 2 {
		t.Fatalf("nullable hash rows %s got=%d err=%v", variant, got, err)
	}
}
