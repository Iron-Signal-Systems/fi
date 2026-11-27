// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"errors"
	"strings"
	"testing"
)

func TestSORPostgreSQLDatabasePrivilegeObserverExactOwnedMatch(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	catalog :=
		testSORPostgreSQLDatabasePrivilegeCatalogFacts()

	calls := 0

	facts, err :=
		observeSORPostgreSQLDatabasePrivileges(
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

				switch {
				case strings.Contains(
					query,
					"pg_catalog.pg_default_acl",
				):
					if expectedFields !=
						sorPostgreSQLDatabaseDefaultPrivilegeFieldCount {
						t.Fatalf(
							"default expectedFields = %d, want %d",
							expectedFields,
							sorPostgreSQLDatabaseDefaultPrivilegeFieldCount,
						)
					}

					return testSORPostgreSQLDatabaseDefaultPrivilegeFields(),
						nil

				case strings.Contains(
					query,
					"target_database AS",
				):
					if expectedFields !=
						sorPostgreSQLDatabaseExplicitPrivilegeFieldCount {
						t.Fatalf(
							"explicit expectedFields = %d, want %d",
							expectedFields,
							sorPostgreSQLDatabaseExplicitPrivilegeFieldCount,
						)
					}

					return testSORPostgreSQLDatabaseExplicitPrivilegeFields(),
						nil

				default:
					t.Fatalf(
						"unexpected composed privilege query: %s",
						query,
					)

					return nil, nil
				}
			},
			policy,
			catalog,
		)
	if err != nil {
		t.Fatalf(
			"observe privileges: %v",
			err,
		)
	}

	if calls != 2 {
		t.Fatalf(
			"query count = %d, want 2",
			calls,
		)
	}

	if !facts.Observed {
		t.Fatal(
			"composed privilege observation is not marked observed",
		)
	}

	if !facts.Applicable {
		t.Fatal(
			"composed privilege observation is not marked applicable",
		)
	}

	state :=
		classifySORPostgreSQLDatabasePrivileges(
			policy,
			facts,
		)

	if state !=
		sorPostgreSQLDatabaseResourceOwnedMatch {
		t.Fatalf(
			"composed privilege state = %s, want OWNED_MATCH",
			state,
		)
	}
}

func TestSORPostgreSQLDatabasePrivilegeObserverNotApplicableWithoutPrerequisites(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	tests :=
		[]struct {
			name   string
			mutate func(
				*sorPostgreSQLDatabaseCatalogFacts,
			)
		}{
			{
				name: "owner role absent",
				mutate: func(
					facts *sorPostgreSQLDatabaseCatalogFacts,
				) {
					facts.OwnerRole.Exists = false
				},
			},
			{
				name: "ingest role absent",
				mutate: func(
					facts *sorPostgreSQLDatabaseCatalogFacts,
				) {
					facts.IngestRole.Exists = false
				},
			},
			{
				name: "database absent",
				mutate: func(
					facts *sorPostgreSQLDatabaseCatalogFacts,
				) {
					facts.Database.Exists = false
				},
			},
			{
				name: "schema absent",
				mutate: func(
					facts *sorPostgreSQLDatabaseCatalogFacts,
				) {
					facts.Schema.Exists = false
				},
			},
		}

	for _, test := range tests {
		t.Run(
			test.name,
			func(
				t *testing.T,
			) {
				catalog :=
					testSORPostgreSQLDatabasePrivilegeCatalogFacts()

				test.mutate(
					&catalog,
				)

				calls := 0

				facts, err :=
					observeSORPostgreSQLDatabasePrivileges(
						func(
							string,
							string,
							int,
						) ([]string, error) {
							calls++

							return nil,
								errors.New(
									"query must not run",
								)
						},
						policy,
						catalog,
					)
				if err != nil {
					t.Fatalf(
						"observe privileges: %v",
						err,
					)
				}

				if calls != 0 {
					t.Fatalf(
						"query count = %d, want 0",
						calls,
					)
				}

				if !facts.Observed {
					t.Fatal(
						"non-applicable privilege observation is not observed",
					)
				}

				if facts.Applicable {
					t.Fatal(
						"non-applicable privilege observation is applicable",
					)
				}

				state :=
					classifySORPostgreSQLDatabasePrivileges(
						policy,
						facts,
					)

				if state !=
					sorPostgreSQLDatabaseResourceAbsent {
					t.Fatalf(
						"non-applicable privilege state = %s, want ABSENT",
						state,
					)
				}
			},
		)
	}
}

func TestSORPostgreSQLDatabasePrivilegeObserverExplicitFailureDoesNotPublish(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	catalog :=
		testSORPostgreSQLDatabasePrivilegeCatalogFacts()

	calls := 0

	facts, err :=
		observeSORPostgreSQLDatabasePrivileges(
			func(
				string,
				string,
				int,
			) ([]string, error) {
				calls++

				return nil,
					errors.New(
						"synthetic explicit failure",
					)
			},
			policy,
			catalog,
		)

	if err == nil {
		t.Fatal(
			"explicit observer failure was accepted",
		)
	}

	if calls != 1 {
		t.Fatalf(
			"query count = %d, want 1",
			calls,
		)
	}

	if facts.Observed ||
		facts.Applicable {
		t.Fatalf(
			"failed explicit observation published facts: %#v",
			facts,
		)
	}
}

func TestSORPostgreSQLDatabasePrivilegeObserverDefaultFailureDoesNotPublish(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	catalog :=
		testSORPostgreSQLDatabasePrivilegeCatalogFacts()

	calls := 0

	facts, err :=
		observeSORPostgreSQLDatabasePrivileges(
			func(
				_ string,
				query string,
				_ int,
			) ([]string, error) {
				calls++

				if strings.Contains(
					query,
					"pg_catalog.pg_default_acl",
				) {
					return nil,
						errors.New(
							"synthetic default failure",
						)
				}

				return testSORPostgreSQLDatabaseExplicitPrivilegeFields(),
					nil
			},
			policy,
			catalog,
		)

	if err == nil {
		t.Fatal(
			"default observer failure was accepted",
		)
	}

	if calls != 2 {
		t.Fatalf(
			"query count = %d, want 2",
			calls,
		)
	}

	if facts.Observed ||
		facts.Applicable {
		t.Fatalf(
			"failed default observation published facts: %#v",
			facts,
		)
	}
}

func TestSORPostgreSQLDatabasePrivilegeObserverMergePreservesDrift(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	catalog :=
		testSORPostgreSQLDatabasePrivilegeCatalogFacts()

	facts, err :=
		observeSORPostgreSQLDatabasePrivileges(
			func(
				_ string,
				query string,
				_ int,
			) ([]string, error) {
				if strings.Contains(
					query,
					"pg_catalog.pg_default_acl",
				) {
					fields :=
						testSORPostgreSQLDatabaseDefaultPrivilegeFields()

					fields[15] = "1"

					return fields, nil
				}

				fields :=
					testSORPostgreSQLDatabaseExplicitPrivilegeFields()

				fields[32] = "1"

				return fields, nil
			},
			policy,
			catalog,
		)
	if err != nil {
		t.Fatalf(
			"observe drifted privileges: %v",
			err,
		)
	}

	if facts.UnexpectedExplicitACLGrantCount != 1 {
		t.Fatalf(
			"unexpected explicit ACL count = %d, want 1",
			facts.UnexpectedExplicitACLGrantCount,
		)
	}

	if facts.UnexpectedDefaultACLGrantCount != 1 {
		t.Fatalf(
			"unexpected default ACL count = %d, want 1",
			facts.UnexpectedDefaultACLGrantCount,
		)
	}

	state :=
		classifySORPostgreSQLDatabasePrivileges(
			policy,
			facts,
		)

	if state !=
		sorPostgreSQLDatabaseResourceOwnedDrift {
		t.Fatalf(
			"merged drift state = %s, want OWNED_DRIFT",
			state,
		)
	}
}

func testSORPostgreSQLDatabaseDefaultPrivilegeFields() []string {
	return []string{
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
}

func testSORPostgreSQLDatabaseExplicitPrivilegeFields() []string {
	return []string{
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
}

func testSORPostgreSQLDatabasePrivilegeCatalogFacts() sorPostgreSQLDatabaseCatalogFacts {
	return sorPostgreSQLDatabaseCatalogFacts{
		OwnerRole: sorPostgreSQLDatabaseCatalogRoleFacts{
			Exists: true,
		},

		IngestRole: sorPostgreSQLDatabaseCatalogRoleFacts{
			Exists: true,
		},

		Database: sorPostgreSQLDatabaseCatalogDatabaseFacts{
			Exists: true,
		},

		Schema: sorPostgreSQLDatabaseCatalogSchemaFacts{
			Exists: true,
		},
	}
}
