// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestSORPostgreSQLDatabaseCatalogObserverExactFacts(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	calls := 0

	observer :=
		sorPostgreSQLDatabaseCatalogObserver{
			query: func(
				database string,
				query string,
				expectedFields int,
			) ([]string, error) {
				calls++

				switch {
				case database == "postgres" &&
					strings.Contains(
						query,
						"rolname = 'fi_owner'",
					):
					if expectedFields !=
						sorPostgreSQLDatabaseCatalogRoleFieldCount {
						t.Fatalf(
							"owner expectedFields = %d",
							expectedFields,
						)
					}

					return []string{
							"t",
							"f",
							"f",
							policy.OwnerRole.Comment,
							"-1",
							"f",
							"f",
							"0",
							"t",
							"0",
							"f",
							"f",
							"f",
							"t",
						},
						nil

				case database == "postgres" &&
					strings.Contains(
						query,
						"rolname = 'fi_ingest'",
					):
					if expectedFields !=
						sorPostgreSQLDatabaseCatalogRoleFieldCount {
						t.Fatalf(
							"ingest expectedFields = %d",
							expectedFields,
						)
					}

					return []string{
							"t",
							"f",
							"t",
							policy.IngestRole.Comment,
							"-1",
							"f",
							"f",
							"0",
							"t",
							"0",
							"t",
							"f",
							"f",
							"t",
						},
						nil

				case database == "postgres" &&
					strings.Contains(
						query,
						"FROM pg_catalog.pg_database",
					):
					if expectedFields !=
						sorPostgreSQLDatabaseCatalogDatabaseFieldCount {
						t.Fatalf(
							"database expectedFields = %d",
							expectedFields,
						)
					}

					return []string{
							"t",
							policy.DatabaseOwner,
							policy.DatabaseEncoding,
							policy.DatabaseCollate,
							policy.DatabaseCType,
							policy.DatabaseComment,
						},
						nil

				case database == policy.DatabaseName &&
					strings.Contains(
						query,
						"FROM pg_catalog.pg_namespace",
					):
					if expectedFields !=
						sorPostgreSQLDatabaseCatalogSchemaFieldCount {
						t.Fatalf(
							"schema expectedFields = %d",
							expectedFields,
						)
					}

					return []string{
							"t",
							policy.SchemaOwner,
							policy.SchemaComment,
						},
						nil

				case database == policy.DatabaseName &&
					strings.Contains(
						query,
						"information_schema.tables",
					):
					if expectedFields !=
						sorPostgreSQLDatabaseCatalogFoundationFieldCount {
						t.Fatalf(
							"foundation expectedFields = %d",
							expectedFields,
						)
					}

					return []string{
							"49",
							"0",
							"0",
						},
						nil

				default:
					return nil,
						fmt.Errorf(
							"unexpected synthetic query against %q: %s",
							database,
							query,
						)
				}
			},
		}

	facts, err :=
		observer.Observe(
			policy,
		)
	if err != nil {
		t.Fatalf(
			"Observe() error = %v",
			err,
		)
	}

	if calls != 5 {
		t.Fatalf(
			"query count = %d, want 5",
			calls,
		)
	}

	expected :=
		sorPostgreSQLDatabaseCatalogFacts{
			OwnerRole: sorPostgreSQLDatabaseCatalogRoleFacts{
				BypassRLS:          false,
				CanLogin:           false,
				Comment:            policy.OwnerRole.Comment,
				ConnectionLimit:    -1,
				CreateDB:           false,
				CreateRole:         false,
				Exists:             true,
				GrantedToCount:     0,
				Inherit:            true,
				MemberOfCount:      0,
				PasswordPresent:    false,
				Replication:        false,
				Superuser:          false,
				ValidUntilInfinity: true,
			},

			IngestRole: sorPostgreSQLDatabaseCatalogRoleFacts{
				BypassRLS:          false,
				CanLogin:           true,
				Comment:            policy.IngestRole.Comment,
				ConnectionLimit:    -1,
				CreateDB:           false,
				CreateRole:         false,
				Exists:             true,
				GrantedToCount:     0,
				Inherit:            true,
				MemberOfCount:      0,
				PasswordPresent:    true,
				Replication:        false,
				Superuser:          false,
				ValidUntilInfinity: true,
			},

			Database: sorPostgreSQLDatabaseCatalogDatabaseFacts{
				Collate:  policy.DatabaseCollate,
				Comment:  policy.DatabaseComment,
				CType:    policy.DatabaseCType,
				Encoding: policy.DatabaseEncoding,
				Exists:   true,
				Owner:    policy.DatabaseOwner,
			},

			Schema: sorPostgreSQLDatabaseCatalogSchemaFacts{
				Comment: policy.SchemaComment,
				Exists:  true,
				Owner:   policy.SchemaOwner,
			},

			Foundation: sorPostgreSQLDatabaseCatalogFoundationFacts{
				BadTypedColumns:   0,
				Exists:            true,
				MissingCoreTables: 0,
				SchemaComment:     policy.SchemaComment,
				TableCount:        policy.ExpectedRelationalTableCount,
			},
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

	observation :=
		classifySORPostgreSQLDatabaseCatalog(
			policy,
			facts,
		)

	if observation.OwnerRole !=
		sorPostgreSQLDatabaseResourceOwnedMatch ||
		observation.IngestRole !=
			sorPostgreSQLDatabaseResourceOwnedMatch ||
		observation.Database !=
			sorPostgreSQLDatabaseResourceOwnedMatch ||
		observation.Schema !=
			sorPostgreSQLDatabaseResourceOwnedMatch ||
		observation.RelationalFoundation !=
			sorPostgreSQLDatabaseResourceOwnedMatch {
		t.Fatalf(
			"catalog observation = %#v, want all catalog resources OWNED_MATCH",
			observation,
		)
	}
}

func TestSORPostgreSQLDatabaseCatalogObserverAbsentDatabaseStopsSafely(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	calls := 0

	observer :=
		sorPostgreSQLDatabaseCatalogObserver{
			query: func(
				database string,
				query string,
				expectedFields int,
			) ([]string, error) {
				calls++

				if database != "postgres" {
					t.Fatalf(
						"observer queried absent FI database %q",
						database,
					)
				}

				if strings.Contains(
					query,
					"rolname = 'fi_owner'",
				) {
					return []string{
							"f",
							"f",
							"f",
							"",
							"0",
							"f",
							"f",
							"0",
							"f",
							"0",
							"f",
							"f",
							"f",
							"f",
						},
						nil
				}

				if strings.Contains(
					query,
					"rolname = 'fi_ingest'",
				) {
					return []string{
							"f",
							"f",
							"f",
							"",
							"0",
							"f",
							"f",
							"0",
							"f",
							"0",
							"f",
							"f",
							"f",
							"f",
						},
						nil
				}

				if strings.Contains(
					query,
					"FROM pg_catalog.pg_database",
				) {
					if expectedFields !=
						sorPostgreSQLDatabaseCatalogDatabaseFieldCount {
						t.Fatalf(
							"database expectedFields = %d",
							expectedFields,
						)
					}

					return []string{
							"f",
							"",
							"",
							"",
							"",
							"",
						},
						nil
				}

				t.Fatalf(
					"unexpected query after absent database: %s",
					query,
				)

				return nil, nil
			},
		}

	facts, err :=
		observer.Observe(
			policy,
		)
	if err != nil {
		t.Fatalf(
			"Observe() error = %v",
			err,
		)
	}

	if calls != 3 {
		t.Fatalf(
			"query count = %d, want 3",
			calls,
		)
	}

	if facts.Database.Exists ||
		facts.Schema.Exists ||
		facts.Foundation.Exists {
		t.Fatalf(
			"absent database produced dependent facts: %#v",
			facts,
		)
	}
}

func TestSORPostgreSQLDatabaseCatalogObserverAbsentSchemaStopsSafely(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	calls := 0

	observer :=
		sorPostgreSQLDatabaseCatalogObserver{
			query: func(
				database string,
				query string,
				expectedFields int,
			) ([]string, error) {
				calls++

				if database == "postgres" &&
					strings.Contains(
						query,
						"rolname = 'fi_owner'",
					) {
					return []string{
							"f", "f", "f", "", "0", "f", "f",
							"0", "f", "0", "f", "f", "f", "f",
						},
						nil
				}

				if database == "postgres" &&
					strings.Contains(
						query,
						"rolname = 'fi_ingest'",
					) {
					return []string{
							"f", "f", "f", "", "0", "f", "f",
							"0", "f", "0", "f", "f", "f", "f",
						},
						nil
				}

				if database == "postgres" &&
					strings.Contains(
						query,
						"FROM pg_catalog.pg_database",
					) {
					return []string{
							"t",
							policy.DatabaseOwner,
							policy.DatabaseEncoding,
							policy.DatabaseCollate,
							policy.DatabaseCType,
							policy.DatabaseComment,
						},
						nil
				}

				if database == policy.DatabaseName &&
					strings.Contains(
						query,
						"FROM pg_catalog.pg_namespace",
					) {
					return []string{
							"f",
							"",
							"",
						},
						nil
				}

				t.Fatalf(
					"foundation queried after absent schema: %s",
					query,
				)

				return nil, nil
			},
		}

	facts, err :=
		observer.Observe(
			policy,
		)
	if err != nil {
		t.Fatalf(
			"Observe() error = %v",
			err,
		)
	}

	if calls != 4 {
		t.Fatalf(
			"query count = %d, want 4",
			calls,
		)
	}

	if facts.Schema.Exists ||
		facts.Foundation.Exists {
		t.Fatalf(
			"absent schema produced foundation facts: %#v",
			facts,
		)
	}
}

func TestSORPostgreSQLDatabaseCatalogObserverSQLContracts(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	roleSQL :=
		buildSORPostgreSQLDatabaseCatalogRoleQuery(
			policy.IngestRole.Name,
		)

	for _, required := range []string{
		"pg_catalog.pg_authid",
		"pg_catalog.pg_auth_members",
		"membership.roleid = target.oid",
		"membership.member = target.oid",
		"rolpassword IS NOT NULL",
		"rolvaliduntil IS NULL",
		"pg_catalog.shobj_description",
	} {
		if !strings.Contains(
			roleSQL,
			required,
		) {
			t.Fatalf(
				"role SQL missing %q",
				required,
			)
		}
	}

	databaseSQL :=
		buildSORPostgreSQLDatabaseCatalogDatabaseQuery(
			policy.DatabaseName,
		)

	for _, required := range []string{
		"pg_catalog.pg_database",
		"pg_catalog.pg_get_userbyid",
		"pg_catalog.pg_encoding_to_char",
		"pg_catalog.shobj_description",
	} {
		if !strings.Contains(
			databaseSQL,
			required,
		) {
			t.Fatalf(
				"database SQL missing %q",
				required,
			)
		}
	}

	schemaSQL :=
		buildSORPostgreSQLDatabaseCatalogSchemaQuery(
			policy.SchemaName,
		)

	for _, required := range []string{
		"pg_catalog.pg_namespace",
		"pg_catalog.pg_get_userbyid",
		"pg_catalog.obj_description",
	} {
		if !strings.Contains(
			schemaSQL,
			required,
		) {
			t.Fatalf(
				"schema SQL missing %q",
				required,
			)
		}
	}

	foundationSQL, err :=
		buildSORPostgreSQLDatabaseCatalogFoundationQuery(
			policy,
		)
	if err != nil {
		t.Fatalf(
			"build foundation SQL: %v",
			err,
		)
	}

	for _, required := range []string{
		"information_schema.tables",
		"information_schema.columns",
		"table_type = 'BASE TABLE'",
		"data_type IN ('json', 'jsonb', 'xml')",
		"'recorded_generation'",
		"'windows_security_event'",
	} {
		if !strings.Contains(
			foundationSQL,
			required,
		) {
			t.Fatalf(
				"foundation SQL missing %q",
				required,
			)
		}
	}
}

func TestSORPostgreSQLDatabaseCatalogObserverStrictParsing(
	t *testing.T,
) {
	_, err :=
		parseSORPostgreSQLDatabaseCatalogRoleFacts(
			[]string{
				"t",
				"not-a-bool",
				"f",
				"",
				"-1",
				"f",
				"f",
				"0",
				"t",
				"0",
				"f",
				"f",
				"f",
				"t",
			},
		)

	if err == nil {
		t.Fatal(
			"invalid role boolean was accepted",
		)
	}

	_, err =
		parseSORPostgreSQLDatabaseCatalogFoundationFacts(
			[]string{
				"49",
				"-1",
				"0",
			},
		)

	if err == nil {
		t.Fatal(
			"negative relational count was accepted",
		)
	}

	_, err =
		parseSORPostgreSQLDatabaseCatalogDatabaseFacts(
			[]string{
				"t",
				"fi_owner",
			},
		)

	if err == nil {
		t.Fatal(
			"short database result was accepted",
		)
	}
}

func TestSORPostgreSQLDatabaseCatalogObserverQuotesSQLLiteral(
	t *testing.T,
) {
	actual :=
		quoteSORPostgreSQLDatabaseSQLLiteral(
			"fi'owner",
		)

	expected :=
		"'fi''owner'"

	if actual != expected {
		t.Fatalf(
			"quoted literal = %q, want %q",
			actual,
			expected,
		)
	}
}
