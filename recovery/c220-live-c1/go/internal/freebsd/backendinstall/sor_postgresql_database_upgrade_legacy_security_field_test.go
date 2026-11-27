// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"strings"
	"testing"
)

func testLegacySORSecurityFieldPolicyAndFacts() (sorPostgreSQLDatabasePolicy, sorPostgreSQLDatabaseCatalogFacts) {
	policy := sorPostgreSQLDatabasePolicy{
		DatabaseName:                 "fi",
		DatabaseOwner:                "fi_owner",
		DatabaseEncoding:             "UTF8",
		DatabaseCollate:              "C",
		DatabaseCType:                "C",
		SchemaName:                   "fi",
		SchemaOwner:                  "fi_owner",
		ExpectedRelationalTableCount: 49,
		OwnerRole: sorPostgreSQLDatabaseRolePolicy{
			Name: "fi_owner", Inherit: true, ConnectionLimit: -1,
		},
		IngestRole: sorPostgreSQLDatabaseRolePolicy{
			Name: "fi_ingest", Inherit: true, ConnectionLimit: -1,
			CanLogin: true, PasswordRequired: true,
		},
	}
	facts := sorPostgreSQLDatabaseCatalogFacts{
		OwnerRole: sorPostgreSQLDatabaseCatalogRoleFacts{
			Exists: true, Inherit: true, ConnectionLimit: -1,
		},
		IngestRole: sorPostgreSQLDatabaseCatalogRoleFacts{
			Exists: true, Inherit: true, ConnectionLimit: -1,
			CanLogin: true, PasswordPresent: true,
		},
		Database: sorPostgreSQLDatabaseCatalogDatabaseFacts{
			Exists: true, Owner: "fi_owner", Encoding: "UTF8", Collate: "C", CType: "C",
		},
		Schema: sorPostgreSQLDatabaseCatalogSchemaFacts{
			Exists: true, Owner: "fi_owner",
		},
		Foundation: sorPostgreSQLDatabaseCatalogFoundationFacts{
			Exists: true, TableCount: 49,
		},
	}
	return policy, facts
}

func TestLegacySORSecurityFieldOwnershipPreflight(t *testing.T) {
	for _, tc := range []struct {
		name      string
		alter     func(*sorPostgreSQLDatabaseCatalogFacts)
		catalog   []string
		wantError bool
	}{
		{name: "valid unmarked legacy SOR"},
		{name: "marked owner role", alter: func(f *sorPostgreSQLDatabaseCatalogFacts) { f.OwnerRole.Comment = "FI-MANAGED" }, wantError: true},
		{name: "marked schema", alter: func(f *sorPostgreSQLDatabaseCatalogFacts) { f.Schema.Comment = "FI-MANAGED" }, wantError: true},
		{name: "modified ingest role", alter: func(f *sorPostgreSQLDatabaseCatalogFacts) { f.IngestRole.Superuser = true }, wantError: true},
		{name: "wrong table count", alter: func(f *sorPostgreSQLDatabaseCatalogFacts) { f.Foundation.TableCount = 48 }, wantError: true},
		{name: "unexpected columns", alter: func(f *sorPostgreSQLDatabaseCatalogFacts) { f.Foundation.BadTypedColumns = 1 }, wantError: true},
		{name: "foreign table ownership", catalog: []string{"t", "t", "t", "t", "49", "48"}, wantError: true},
		{name: "partially marked", catalog: []string{"t", "t", "t", "f", "49", "49"}, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy, facts := testLegacySORSecurityFieldPolicyAndFacts()
			if tc.alter != nil {
				tc.alter(&facts)
			}
			calls := 0
			query := func(database, sql string, fields int) ([]string, error) {
				calls++
				if database != "fi" || fields != 6 || sql != sorPostgreSQLLegacySecurityFieldAuthorityQuery {
					t.Fatalf("unexpected catalog query")
				}
				if tc.catalog != nil {
					return tc.catalog, nil
				}
				return []string{"t", "t", "t", "t", "49", "49"}, nil
			}
			err := verifyLegacySORPostgreSQLSecurityFieldOwnership(policy, facts, query)
			if (err != nil) != tc.wantError {
				t.Fatalf("error=%v, want error=%t", err, tc.wantError)
			}
			if !tc.wantError && calls != 1 {
				t.Fatalf("queries=%d, want=1", calls)
			}
		})
	}
}

func TestSORSecurityFieldConstraintCatalogIgnoresPostgreSQL18NotNullEntries(t *testing.T) {
	if !strings.Contains(sorPostgreSQLSecurityFieldConstraintsQuery,
		"count(*) FILTER (WHERE contype IN ('p', 'f', 'c'))") {
		t.Fatal("constraint query must exclude PostgreSQL 18 NOT NULL entries")
	}
}
