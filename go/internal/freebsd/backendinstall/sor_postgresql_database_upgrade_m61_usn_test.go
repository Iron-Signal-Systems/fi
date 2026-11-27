// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package backendinstall

import (
	"errors"
	"strings"
	"testing"
)

func TestSORM61USNUpgradeStates(t *testing.T) {
	for _, tc := range []struct {
		name        string
		start       []string
		wantCalls   int
		wantFailure bool
	}{
		{name: "legacy receives canonical migration", start: []string{"0", "0", "0", "0", "0", "0", "0", "fi_owner", "fi_owner", "NO"}, wantCalls: 1},
		{name: "interrupted validation resumes", start: []string{"3", "3", "1", "1", "3", "3", "1", "fi_owner", "fi_owner", "YES"}, wantCalls: 1},
		{name: "completed is idempotent", start: []string{"3", "3", "1", "1", "3", "3", "3", "fi_owner", "fi_owner", "YES"}, wantCalls: 0},
		{name: "partial column install fails closed", start: []string{"2", "2", "0", "0", "0", "0", "0", "fi_owner", "fi_owner", "NO"}, wantFailure: true},
		{name: "wrong column type fails closed", start: []string{"3", "2", "1", "1", "3", "3", "0", "fi_owner", "fi_owner", "YES"}, wantFailure: true},
		{name: "constraint names match but definitions differ", start: []string{"3", "3", "1", "1", "3", "2", "3", "fi_owner", "fi_owner", "YES"}, wantFailure: true},
		{name: "constraint names match but definitions differ before validation", start: []string{"3", "3", "1", "1", "3", "2", "1", "fi_owner", "fi_owner", "YES"}, wantFailure: true},
		{name: "unexpected nullable column default", start: []string{"3", "2", "1", "1", "3", "3", "3", "fi_owner", "fi_owner", "YES"}, wantFailure: true},
		{name: "incorrect nullable operation ID", start: []string{"3", "3", "1", "1", "3", "3", "3", "fi_owner", "fi_owner", "NO"}, wantFailure: true},
		{name: "foreign ownership fails closed", start: []string{"0", "0", "0", "0", "0", "0", "0", "postgres", "fi_owner", "NO"}, wantFailure: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := append([]string(nil), tc.start...)
			calls := 0
			query := func(database, sql string, fields int) ([]string, error) {
				if database != "fi" || sql != sorM61USNCatalogQuery || fields != 10 {
					t.Fatal("unexpected catalog query")
				}
				return append([]string(nil), state...), nil
			}
			execute := func(database, role string, body []byte) error {
				calls++
				if database != "fi" || role != "fi_owner" {
					t.Fatal("unexpected database role")
				}
				if string(body) != sorPostgreSQLDatabaseMigration0005Asset &&
					string(body) != sorM61USNValidateSQL {
					t.Fatal("unexpected migration input")
				}
				state = []string{"3", "3", "1", "1", "3", "3", "3", "fi_owner", "fi_owner", "YES"}
				return nil
			}
			asset := sorPostgreSQLDatabaseMigrationAsset{
				Name: "0005_usn_capture_binding.sql", SHA256: sorPostgreSQLDatabaseMigration0005SHA256,
				SQL: sorPostgreSQLDatabaseMigration0005Asset,
			}
			err := upgradeSORM61USNWith(asset, query, execute)
			if (err != nil) != tc.wantFailure {
				t.Fatalf("error=%v, want failure=%t", err, tc.wantFailure)
			}
			if calls != tc.wantCalls {
				t.Fatalf("migration calls=%d, want=%d", calls, tc.wantCalls)
			}
		})
	}
}

func TestSORM61USNUpgradeRejectsExecutorFailure(t *testing.T) {
	asset := sorPostgreSQLDatabaseMigrationAsset{
		Name: "0005_usn_capture_binding.sql", SHA256: sorPostgreSQLDatabaseMigration0005SHA256,
		SQL: sorPostgreSQLDatabaseMigration0005Asset,
	}
	query := func(_, _ string, _ int) ([]string, error) {
		return []string{"0", "0", "0", "0", "0", "0", "0", "fi_owner", "fi_owner", "NO"}, nil
	}
	err := upgradeSORM61USNWith(asset, query, func(string, string, []byte) error {
		return errors.New("synthetic migration failure")
	})
	if err == nil || !strings.Contains(err.Error(), "synthetic migration failure") {
		t.Fatalf("expected fail-closed execution, got %v", err)
	}
}

func TestSORM61USNMigratesLargeTablesWithoutExclusiveValidationScan(t *testing.T) {
	asset := sorPostgreSQLDatabaseMigration0005Asset
	if !strings.Contains(asset, "COMMIT;\n\n-- Each statement") ||
		!strings.Contains(asset, "NOT VALID") ||
		strings.Count(asset, "VALIDATE CONSTRAINT") != 3 ||
		!strings.Contains(asset, "SET LOCAL lock_timeout") {
		t.Fatal("M6.1 migration must commit metadata phase before validating all constraints")
	}
}

func TestSORM61CatalogRequiresCanonicalPostgreSQL18Definitions(t *testing.T) {
	for _, expected := range []string{
		"pg_catalog.pg_get_constraintdef(c.oid,false)",
		"FOREIGN KEY (root_ntfs_object_id) REFERENCES fi.ntfs_object(ntfs_object_id)",
		"source_batch_sha256 IS NULL) AND (correlation_sha256 IS NULL)",
		"usn_read_operation_id <> ''::text",
		"source_batch_sha256 IS NULL) OR (octet_length(source_batch_sha256) = 32)",
		"NOT c.condeferrable AND NOT c.condeferred",
		"AND is_nullable='YES' AND column_default IS NULL",
	} {
		if !strings.Contains(sorM61USNCatalogQuery, expected) {
			t.Fatalf("canonical catalog query missing %q", expected)
		}
	}
}

func TestSORM61CatalogRejectsUnexpectedFieldCountAndDefinitionDrift(t *testing.T) {
	for _, tc := range []struct {
		name   string
		fields []string
	}{
		{name: "missing field", fields: []string{"3", "3", "1", "1", "3", "3", "3", "fi_owner", "fi_owner"}},
		{name: "extra field", fields: []string{"3", "3", "1", "1", "3", "3", "3", "fi_owner", "fi_owner", "YES", "extra"}},
		{name: "negative definition count", fields: []string{"3", "3", "1", "1", "3", "-1", "3", "fi_owner", "fi_owner", "YES"}},
		{name: "non-numeric definition count", fields: []string{"3", "3", "1", "1", "3", "bad", "3", "fi_owner", "fi_owner", "YES"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			query := func(database, sql string, n int) ([]string, error) {
				if database != "fi" || sql != sorM61USNCatalogQuery || n != 10 {
					t.Fatal("unexpected catalog query")
				}
				return tc.fields, nil
			}
			if _, err := inspectSORM61USNCatalog(query); err == nil {
				t.Fatal("unexpected catalog shape or values accepted")
			}
		})
	}
}
