// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"reflect"
	"strings"
	"testing"
)

func TestSORPostgreSQLDatabaseExplicitPrivilegeObserverExactFacts(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	fields :=
		[]string{
			"t",
			"f",
			"f",
			"f",
			"f",
			"f",
			"f",
			"t",
			"f",
			"f",
			"f",
			"f",
			"f",
			"49",
			"49",
			"49",
			"0",
			"0",
			"0",
			"0",
			"0",
			"0",
			"0",
			"0",
			"0",
			"0",
			"12",
			"12",
			"12",
			"0",
			"0",
			"0",
			"0",
		}

	calls := 0

	facts, err :=
		observeSORPostgreSQLDatabaseExplicitPrivileges(
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
					sorPostgreSQLDatabaseExplicitPrivilegeFieldCount {
					t.Fatalf(
						"expectedFields = %d, want %d",
						expectedFields,
						sorPostgreSQLDatabaseExplicitPrivilegeFieldCount,
					)
				}

				if !strings.Contains(
					query,
					"pg_catalog.has_table_privilege",
				) {
					t.Fatal(
						"explicit privilege query missing table privilege checks",
					)
				}

				return fields, nil
			},
			policy,
		)
	if err != nil {
		t.Fatalf(
			"observe explicit privileges: %v",
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
			DatabaseConnect:            true,
			DatabaseConnectGrantOption: false,
			DatabaseCreate:             false,
			DatabaseTemporary:          false,
			PublicDatabaseConnect:      false,
			PublicDatabaseCreate:       false,
			PublicDatabaseTemporary:    false,

			SchemaUsage:               true,
			SchemaUsageGrantOption:    false,
			SchemaCreate:              false,
			PublicSchemaUsage:         false,
			PublicSchemaCreate:        false,
			PublicDefaultSchemaCreate: false,

			TableCount:                  49,
			TableSelectCount:            49,
			TableInsertCount:            49,
			TableSelectGrantOptionCount: 0,
			TableInsertGrantOptionCount: 0,
			TableUpdateCount:            0,
			TableDeleteCount:            0,
			TableTruncateCount:          0,
			TableReferencesCount:        0,
			TableTriggerCount:           0,
			TableMaintainCount:          0,
			TableColumnUpdateCount:      0,
			TableColumnReferencesCount:  0,

			SequenceCount:                  12,
			SequenceUsageCount:             12,
			SequenceSelectCount:            12,
			SequenceUsageGrantOptionCount:  0,
			SequenceSelectGrantOptionCount: 0,
			SequenceUpdateCount:            0,

			UnexpectedExplicitACLGrantCount: 0,
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

func TestSORPostgreSQLDatabaseExplicitPrivilegeObserverSQLContracts(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	query :=
		buildSORPostgreSQLDatabaseExplicitPrivilegeQuery(
			policy,
		)

	required :=
		[]string{
			"pg_catalog.has_database_privilege",
			"CONNECT WITH GRANT OPTION",
			"pg_catalog.has_schema_privilege",
			"USAGE WITH GRANT OPTION",
			"pg_catalog.has_table_privilege",
			"SELECT WITH GRANT OPTION",
			"INSERT WITH GRANT OPTION",
			"'MAINTAIN'",
			"pg_catalog.has_any_column_privilege",
			"pg_catalog.has_sequence_privilege",
			"pg_catalog.aclexplode",
			"attribute.attacl",
			"acl.grantee <> 0",
			"acl.grantee <> table_object.relowner",
			"acl.grantee <> sequence_object.relowner",
			"acl.privilege_type = 'CREATE'",
		}

	for _, fragment := range required {
		if !strings.Contains(
			query,
			fragment,
		) {
			t.Fatalf(
				"explicit ACL SQL missing %q",
				fragment,
			)
		}
	}
}

func TestSORPostgreSQLDatabaseExplicitPrivilegeObserverRejectsBadBoolean(
	t *testing.T,
) {
	fields :=
		make(
			[]string,
			sorPostgreSQLDatabaseExplicitPrivilegeFieldCount,
		)

	for index := range fields {
		fields[index] = "0"
	}

	fields[0] = "not-a-bool"

	_, err :=
		parseSORPostgreSQLDatabaseExplicitPrivilegeFacts(
			fields,
		)

	if err == nil {
		t.Fatal(
			"invalid explicit privilege boolean was accepted",
		)
	}
}

func TestSORPostgreSQLDatabaseExplicitPrivilegeObserverRejectsNegativeCount(
	t *testing.T,
) {
	fields :=
		[]string{
			"t",
			"f",
			"f",
			"f",
			"f",
			"f",
			"f",
			"t",
			"f",
			"f",
			"f",
			"f",
			"f",
			"-1",
			"0",
			"0",
			"0",
			"0",
			"0",
			"0",
			"0",
			"0",
			"0",
			"0",
			"0",
			"0",
			"0",
			"0",
			"0",
			"0",
			"0",
			"0",
			"0",
		}

	_, err :=
		parseSORPostgreSQLDatabaseExplicitPrivilegeFacts(
			fields,
		)

	if err == nil {
		t.Fatal(
			"negative explicit privilege count was accepted",
		)
	}
}

func TestSORPostgreSQLDatabaseExplicitPrivilegeObserverRejectsWrongFieldCount(
	t *testing.T,
) {
	_, err :=
		parseSORPostgreSQLDatabaseExplicitPrivilegeFacts(
			[]string{
				"t",
			},
		)

	if err == nil {
		t.Fatal(
			"short explicit privilege result was accepted",
		)
	}
}

func TestSORPostgreSQLDatabaseExplicitPrivilegeObserverQuotesAuthorityNames(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	policy.DatabaseName = "fi'db"
	policy.OwnerRole.Name = "fi'owner"
	policy.IngestRole.Name = "fi'ingest"
	policy.SchemaName = "fi'schema"

	query :=
		buildSORPostgreSQLDatabaseExplicitPrivilegeQuery(
			policy,
		)

	for _, expected := range []string{
		"'fi''db'",
		"'fi''owner'",
		"'fi''ingest'",
		"'fi''schema'",
	} {
		if !strings.Contains(
			query,
			expected,
		) {
			t.Fatalf(
				"explicit ACL query missing quoted authority %q",
				expected,
			)
		}
	}
}
