// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"reflect"
	"strings"
	"testing"
)

func TestSORPostgreSQLDatabaseDefaultPrivilegeObserverExactFacts(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	fields :=
		[]string{
			"t",
			"t",
			"f",
			"f",
			"f",
			"f",
			"f",
			"f",
			"f",
			"f",
			"t",
			"t",
			"f",
			"f",
			"f",
			"0",
		}

	calls := 0

	facts, err :=
		observeSORPostgreSQLDatabaseDefaultPrivileges(
			func(
				database string,
				query string,
				expectedFields int,
			) ([]string, error) {
				calls++

				if database !=
					policy.DatabaseName {
					t.Fatalf(
						"database = %q, want %q",
						database,
						policy.DatabaseName,
					)
				}

				if expectedFields !=
					sorPostgreSQLDatabaseDefaultPrivilegeFieldCount {
					t.Fatalf(
						"expectedFields = %d, want %d",
						expectedFields,
						sorPostgreSQLDatabaseDefaultPrivilegeFieldCount,
					)
				}

				if !strings.Contains(
					query,
					"pg_catalog.pg_default_acl",
				) {
					t.Fatal(
						"default privilege query missing pg_default_acl",
					)
				}

				return fields, nil
			},
			policy,
		)
	if err != nil {
		t.Fatalf(
			"observe default privileges: %v",
			err,
		)
	}

	if calls != 1 {
		t.Fatalf(
			"query count = %d, want 1",
			calls,
		)
	}

	expected :=
		sorPostgreSQLDatabasePrivilegeFacts{
			DefaultTableSelect:            true,
			DefaultTableInsert:            true,
			DefaultTableSelectGrantOption: false,
			DefaultTableInsertGrantOption: false,
			DefaultTableUpdate:            false,
			DefaultTableDelete:            false,
			DefaultTableTruncate:          false,
			DefaultTableReferences:        false,
			DefaultTableTrigger:           false,
			DefaultTableMaintain:          false,

			DefaultSequenceUsage:             true,
			DefaultSequenceSelect:            true,
			DefaultSequenceUsageGrantOption:  false,
			DefaultSequenceSelectGrantOption: false,
			DefaultSequenceUpdate:            false,

			UnexpectedDefaultACLGrantCount: 0,
		}

	if !reflect.DeepEqual(
		facts,
		expected,
	) {
		t.Fatalf(
			"facts = %#v, want %#v",
			facts,
			expected,
		)
	}
}

func TestSORPostgreSQLDatabaseDefaultPrivilegeObserverSQLContracts(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	query :=
		buildSORPostgreSQLDatabaseDefaultPrivilegeQuery(
			policy,
		)

	required :=
		[]string{
			"pg_catalog.pg_default_acl",
			"default_acl.defaclrole = roles.owner_oid",
			"default_acl.defaclnamespace = target_schema.oid",
			"default_acl.defaclobjtype = 'r'",
			"default_acl.defaclobjtype = 'S'",
			"pg_catalog.aclexplode",
			"acl.grantor = roles.owner_oid",
			"acl.grantee = roles.ingest_oid",
			"acl.privilege_type = 'SELECT'",
			"acl.privilege_type = 'INSERT'",
			"acl.privilege_type = 'USAGE'",
			"acl.privilege_type = 'MAINTAIN'",
			"AND NOT acl.is_grantable",
			"AND acl.is_grantable",
			"default_acl.defaclobjtype IN ('r', 'S')",
		}

	for _, fragment := range required {
		if !strings.Contains(
			query,
			fragment,
		) {
			t.Fatalf(
				"default ACL SQL missing %q",
				fragment,
			)
		}
	}
}

func TestSORPostgreSQLDatabaseDefaultPrivilegeObserverRejectsBadBoolean(
	t *testing.T,
) {
	fields :=
		[]string{
			"bad",
			"t",
			"f",
			"f",
			"f",
			"f",
			"f",
			"f",
			"f",
			"f",
			"t",
			"t",
			"f",
			"f",
			"f",
			"0",
		}

	_, err :=
		parseSORPostgreSQLDatabaseDefaultPrivilegeFacts(
			fields,
		)

	if err == nil {
		t.Fatal(
			"invalid default privilege boolean was accepted",
		)
	}
}

func TestSORPostgreSQLDatabaseDefaultPrivilegeObserverRejectsNegativeCount(
	t *testing.T,
) {
	fields :=
		[]string{
			"t",
			"t",
			"f",
			"f",
			"f",
			"f",
			"f",
			"f",
			"f",
			"f",
			"t",
			"t",
			"f",
			"f",
			"f",
			"-1",
		}

	_, err :=
		parseSORPostgreSQLDatabaseDefaultPrivilegeFacts(
			fields,
		)

	if err == nil {
		t.Fatal(
			"negative unexpected default ACL count was accepted",
		)
	}
}

func TestSORPostgreSQLDatabaseDefaultPrivilegeObserverRejectsWrongFieldCount(
	t *testing.T,
) {
	_, err :=
		parseSORPostgreSQLDatabaseDefaultPrivilegeFacts(
			[]string{
				"t",
			},
		)

	if err == nil {
		t.Fatal(
			"short default privilege result was accepted",
		)
	}
}

func TestSORPostgreSQLDatabaseDefaultPrivilegeObserverQuotesAuthorityNames(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	policy.OwnerRole.Name = "fi'owner"
	policy.IngestRole.Name = "fi'ingest"
	policy.SchemaName = "fi'schema"

	query :=
		buildSORPostgreSQLDatabaseDefaultPrivilegeQuery(
			policy,
		)

	for _, expected := range []string{
		"'fi''owner'",
		"'fi''ingest'",
		"'fi''schema'",
	} {
		if !strings.Contains(
			query,
			expected,
		) {
			t.Fatalf(
				"default ACL query missing quoted authority %q",
				expected,
			)
		}
	}
}
