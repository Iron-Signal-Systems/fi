// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"errors"
	"strings"
	"testing"
)

func TestSORPostgreSQLSecurityFieldIndexUpgrade(t *testing.T) {
	for _, tc := range []struct {
		name           string
		initial        bool
		after          bool
		corruptIndex   bool
		badConstraints bool
		executeError   bool
		wantError      bool
		wantExec       int
	}{
		{name: "drop valid index", initial: true, after: false, wantExec: 1},
		{name: "previously removed", initial: false, after: false, wantExec: 0},
		{name: "reject foreign index definition", initial: true, corruptIndex: true, wantError: true},
		{name: "reject constraint drift", initial: true, badConstraints: true, wantError: true},
		{name: "executor failure", initial: true, executeError: true, wantError: true, wantExec: 1},
		{name: "reject incomplete drop", initial: true, after: true, wantError: true, wantExec: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			indexChecks := 0
			query := func(database, sql string, fields int) ([]string, error) {
				if database != "fi" {
					t.Fatalf("database = %q", database)
				}
				switch sql {
				case sorPostgreSQLSecurityFieldTableQuery:
					if fields != 2 {
						t.Fatalf("table fields = %d", fields)
					}
					return []string{"fi_owner", "r"}, nil
				case sorPostgreSQLSecurityFieldConstraintsQuery:
					if fields != 4 {
						t.Fatalf("constraint fields = %d", fields)
					}
					if tc.badConstraints {
						return []string{"1", "0", "1", "2"}, nil
					}
					return []string{"1", "1", "1", "3"}, nil
				case sorPostgreSQLSecurityFieldIndexQuery:
					if fields != 8 {
						t.Fatalf("index fields = %d", fields)
					}
					indexChecks++
					present := tc.initial
					if indexChecks > 1 {
						present = tc.after
					}
					if !present {
						return []string{"f", "", "", "", "", "", "f", "f"}, nil
					}
					definition := "CREATE INDEX windows_security_event_field_name_idx ON fi.windows_security_event_field USING btree (name)"
					if tc.corruptIndex {
						definition += " INCLUDE (value)"
					}
					return []string{"t", "fi", "windows_security_event_field", definition, "btree", "fi_owner", "f", "f"}, nil
				default:
					t.Fatalf("unexpected query: %s", sql)
					return nil, nil
				}
			}
			execute := func(database, role string, sql []byte) error {
				calls++
				if database != "fi" || role != "fi_owner" ||
					!strings.Contains(string(sql), "DROP INDEX CONCURRENTLY fi.windows_security_event_field_name_idx;") {
					t.Fatal("unexpected SQL execution")
				}
				if tc.executeError {
					return errors.New("synthetic failure")
				}
				return nil
			}
			err := upgradeSORPostgreSQLSecurityFieldIndexWith(
				sorPostgreSQLDatabasePolicy{DatabaseName: "fi", OwnerRole: sorPostgreSQLDatabaseRolePolicy{Name: "fi_owner"}},
				sorPostgreSQLDatabaseMigrationAsset{Name: "0004_security_field_name_index.sql", SHA256: sorPostgreSQLDatabaseMigration0004SHA256, SQL: "DROP INDEX CONCURRENTLY fi.windows_security_event_field_name_idx;"},
				query, execute,
			)
			if (err != nil) != tc.wantError {
				t.Fatalf("error = %v, wantError=%v", err, tc.wantError)
			}
			if calls != tc.wantExec {
				t.Fatalf("execute calls=%d, want=%d", calls, tc.wantExec)
			}
		})
	}
}

func TestSORPostgreSQLSecurityFieldIndexUpgradeRejectsMissingExecutors(t *testing.T) {
	policy := sorPostgreSQLDatabasePolicy{DatabaseName: "fi", OwnerRole: sorPostgreSQLDatabaseRolePolicy{Name: "fi_owner"}}
	asset := sorPostgreSQLDatabaseMigrationAsset{Name: "0004_security_field_name_index.sql", SHA256: sorPostgreSQLDatabaseMigration0004SHA256}
	if err := upgradeSORPostgreSQLSecurityFieldIndexWith(policy, asset, nil, func(string, string, []byte) error { return nil }); err == nil {
		t.Fatal("missing query executor accepted")
	}
	if err := upgradeSORPostgreSQLSecurityFieldIndexWith(policy, asset, func(string, string, int) ([]string, error) { return nil, nil }, nil); err == nil {
		t.Fatal("missing SQL executor accepted")
	}
}
