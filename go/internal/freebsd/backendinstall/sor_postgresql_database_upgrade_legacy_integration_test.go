// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// This test is opt-in and only uses the known, isolated PostgreSQL fixture
// inside fi-dev. It never connects to fi-backend-b's production SOR jail.
// On the first run it removes the fixture's secondary index. On later runs
// it verifies the no-op/retry path without executing the migration again.
func TestLegacySORSecurityFieldIndexIsolatedIntegration(t *testing.T) {
	if os.Getenv("FI_TEST_LEGACY_SOR_ISOLATED") != "1" {
		t.Skip("isolated legacy SOR fixture integration test is opt-in")
	}

	const base = "/home/jwood/fi-security-field-benchmark.XEzxWV"
	const socket = base + "/socket"
	const data = base + "/data"

	if host, err := os.Hostname(); err != nil || strings.Split(host, ".")[0] != "fi-dev" {
		t.Fatalf("isolated test requires fi-dev, hostname=%q err=%v", host, err)
	}
	if os.Geteuid() == 0 {
		t.Fatal("isolated test must not run as root")
	}

	psql := func(database, statement string) ([]byte, error) {
		command := exec.Command(
			"psql", "-X", "-q", "-t", "--csv", "-w",
			"-U", "jwood", "-h", socket, "-p", "55439",
			"-v", "ON_ERROR_STOP=1", "-d", database,
			"-c", statement,
		)
		output, err := command.CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("isolated psql %s: %w: %s", database, err, strings.TrimSpace(string(output)))
		}
		return output, nil
	}
	scalar := func(database, statement string) string {
		t.Helper()
		output, err := psql(database, statement)
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(output))
	}

	// Validate the cluster and the EMPTY canonical fixture before any SQL
	// mutation. This deliberately rejects the production server and database.
	if got := scalar("postgres", "SHOW data_directory;"); got != data {
		t.Fatalf("unexpected PostgreSQL data directory %q, want %q", got, data)
	}
	if got := scalar("postgres", "SHOW listen_addresses;"); got != "" {
		t.Fatalf("isolated cluster must not listen on TCP; got %q", got)
	}
	if got := scalar("fi", "SELECT current_database() || ':' || current_user;"); got != "fi:jwood" {
		t.Fatalf("unexpected fixture identity %q", got)
	}
	if got := scalar("fi", "SELECT count(*) FROM fi.recorded_generation;"); got != "0" {
		t.Fatalf("fixture contains recorded generations: %s", got)
	}

	query := func(database, statement string, expectedFields int) ([]string, error) {
		output, err := psql(database, statement)
		if err != nil {
			return nil, err
		}
		return parseSORPostgreSQLDatabasePSQLOutput(output, expectedFields)
	}

	policy := testSORPostgreSQLDatabasePolicy(t)
	// The isolated fixture was deliberately created with C/C. FI's live
	// installer policy expects C.UTF-8/C.UTF-8; this test validates the SQL
	// migration path, NOT the production collation preflight.
	policy.DatabaseCollate = "C"
	policy.DatabaseCType = "C"

	assets := sorPostgreSQLDatabaseMigrationAssets()
	if err := validateSORPostgreSQLDatabaseMigrations(policy, assets); err != nil {
		t.Fatalf("validate canonical migration assets: %v", err)
	}
	if len(assets) != 4 || assets[3].Name != "0004_security_field_name_index.sql" {
		t.Fatal("unexpected canonical migration 0004")
	}

	facts, err := (sorPostgreSQLDatabaseCatalogObserver{query: query}).Observe(policy)
	if err != nil {
		t.Fatalf("observe actual isolated legacy catalog: %v", err)
	}
	if err := verifyLegacySORPostgreSQLSecurityFieldOwnership(policy, facts, query); err != nil {
		t.Fatalf("actual legacy ownership preflight: %v", err)
	}

	indexBefore, err := observeSORPostgreSQLSecurityFieldIndex(query, "fi")
	if err != nil {
		t.Fatalf("inspect initial fixture index: %v", err)
	}

	calls := 0
	execute := func(database, role string, sql []byte) error {
		if database != "fi" || role != "fi_owner" || string(sql) != assets[3].SQL {
			return fmt.Errorf("unexpected database/role/SQL in isolated migration executor")
		}
		calls++
		command := exec.Command(
			"psql", "-X", "-q", "-w", "-U", "jwood",
			"-h", socket, "-p", "55439", "-v", "ON_ERROR_STOP=1",
			"-d", "fi", "-c", "SET ROLE fi_owner;", "-f", "-",
		)
		command.Stdin = bytes.NewReader(sql)
		output, err := command.CombinedOutput()
		if err != nil {
			return fmt.Errorf("isolated migration execution failed: %w: %s", err, strings.TrimSpace(string(output)))
		}
		return nil
	}

	if err := upgradeSORPostgreSQLSecurityFieldIndexWith(policy, assets[3], query, execute); err != nil {
		t.Fatalf("actual isolated migration 0004: %v", err)
	}
	wantCalls := 0
	if indexBefore {
		wantCalls = 1
	}
	if calls != wantCalls {
		t.Fatalf("migration executions=%d, want=%d", calls, wantCalls)
	}

	indexAfter, err := observeSORPostgreSQLSecurityFieldIndex(query, "fi")
	if err != nil || indexAfter {
		t.Fatalf("index after migration: exists=%t err=%v", indexAfter, err)
	}

	// A second execution must be a no-op even when the first actually
	// performed DROP INDEX CONCURRENTLY.
	if err := upgradeSORPostgreSQLSecurityFieldIndexWith(policy, assets[3], query, execute); err != nil {
		t.Fatalf("safe retry after migration: %v", err)
	}
	if calls != wantCalls {
		t.Fatalf("retry unexpectedly ran SQL: executions=%d", calls)
	}

	t.Logf("PASS isolated 49-table legacy preflight; index initially present=%t; migration SQL executions=%d; index removed; retry no-op", indexBefore, calls)
}
