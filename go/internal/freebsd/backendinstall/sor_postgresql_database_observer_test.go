// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestSORPostgreSQLDatabaseObserverExactOwnedMatch(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	queryCalls := 0
	inspectCalls := 0

	observer :=
		sorPostgreSQLDatabaseObserver{
			query: func(
				database string,
				query string,
				expectedFields int,
			) ([]string, error) {
				queryCalls++

				return testSORPostgreSQLDatabaseObserverExactQuery(
					t,
					policy,
					database,
					query,
					expectedFields,
					false,
				)
			},

			inspectPassfile: func(
				observedPolicy sorPostgreSQLDatabasePolicy,
			) (
				sorPostgreSQLDatabasePassfileFacts,
				string,
				error,
			) {
				inspectCalls++

				if observedPolicy.PassfilePath !=
					policy.PassfilePath {
					t.Fatalf(
						"passfile path = %q, want %q",
						observedPolicy.PassfilePath,
						policy.PassfilePath,
					)
				}

				return testSORPostgreSQLDatabasePassfileExactFacts(),
					testSORPostgreSQLDatabaseSecret,
					nil
			},
		}

	observation,
		state,
		err :=
		observer.Observe(
			policy,
		)
	if err != nil {
		t.Fatalf(
			"Observe() error = %v",
			err,
		)
	}

	if queryCalls != 8 {
		t.Fatalf(
			"query count = %d, want 8",
			queryCalls,
		)
	}

	if inspectCalls != 1 {
		t.Fatalf(
			"passfile inspection count = %d, want 1",
			inspectCalls,
		)
	}

	if state !=
		sorPostgreSQLDatabaseOwnedMatch {
		t.Fatalf(
			"database state = %s, want OWNED_MATCH",
			state,
		)
	}

	assertSORPostgreSQLDatabaseObserverAllResources(
		t,
		observation,
		sorPostgreSQLDatabaseResourceOwnedMatch,
	)
}

func TestSORPostgreSQLDatabaseObserverExplicitACLDrift(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	observer :=
		sorPostgreSQLDatabaseObserver{
			query: func(
				database string,
				query string,
				expectedFields int,
			) ([]string, error) {
				return testSORPostgreSQLDatabaseObserverExactQuery(
					t,
					policy,
					database,
					query,
					expectedFields,
					true,
				)
			},

			inspectPassfile: func(
				sorPostgreSQLDatabasePolicy,
			) (
				sorPostgreSQLDatabasePassfileFacts,
				string,
				error,
			) {
				return testSORPostgreSQLDatabasePassfileExactFacts(),
					testSORPostgreSQLDatabaseSecret,
					nil
			},
		}

	observation,
		state,
		err :=
		observer.Observe(
			policy,
		)
	if err != nil {
		t.Fatalf(
			"Observe() error = %v",
			err,
		)
	}

	if observation.Privileges !=
		sorPostgreSQLDatabaseResourceOwnedDrift {
		t.Fatalf(
			"privilege state = %s, want OWNED_DRIFT",
			observation.Privileges,
		)
	}

	if state !=
		sorPostgreSQLDatabaseOwnedDrift {
		t.Fatalf(
			"database state = %s, want OWNED_DRIFT",
			state,
		)
	}
}

func TestSORPostgreSQLDatabaseObserverAbsent(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	queryCalls := 0
	inspectCalls := 0

	observer :=
		sorPostgreSQLDatabaseObserver{
			query: func(
				database string,
				query string,
				expectedFields int,
			) ([]string, error) {
				queryCalls++

				if database != "postgres" {
					return nil,
						fmt.Errorf(
							"unexpected query against absent database %q",
							database,
						)
				}

				switch {
				case expectedFields ==
					sorPostgreSQLDatabaseCatalogRoleFieldCount:

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

				case expectedFields ==
					sorPostgreSQLDatabaseCatalogDatabaseFieldCount:

					return []string{
							"f",
							"",
							"",
							"",
							"",
							"",
						},
						nil

				case expectedFields ==
					sorPostgreSQLDatabaseCredentialFieldCount &&
					strings.Contains(
						query,
						"WITH target_role AS",
					):

					return []string{
							"f",
							"",
						},
						nil

				default:
					return nil,
						fmt.Errorf(
							"unexpected absent-state query: %s",
							query,
						)
				}
			},

			inspectPassfile: func(
				sorPostgreSQLDatabasePolicy,
			) (
				sorPostgreSQLDatabasePassfileFacts,
				string,
				error,
			) {
				inspectCalls++

				return sorPostgreSQLDatabasePassfileFacts{
						Observed: true,
					},
					"",
					nil
			},
		}

	observation,
		state,
		err :=
		observer.Observe(
			policy,
		)
	if err != nil {
		t.Fatalf(
			"Observe() error = %v",
			err,
		)
	}

	if queryCalls != 4 {
		t.Fatalf(
			"query count = %d, want 4",
			queryCalls,
		)
	}

	if inspectCalls != 1 {
		t.Fatalf(
			"passfile inspection count = %d, want 1",
			inspectCalls,
		)
	}

	if state !=
		sorPostgreSQLDatabaseAbsent {
		t.Fatalf(
			"database state = %s, want ABSENT",
			state,
		)
	}

	assertSORPostgreSQLDatabaseObserverAllResources(
		t,
		observation,
		sorPostgreSQLDatabaseResourceAbsent,
	)
}

func TestSORPostgreSQLDatabaseObserverPrivilegeFailureIsUnknown(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	inspectCalls := 0

	observer :=
		sorPostgreSQLDatabaseObserver{
			query: func(
				database string,
				query string,
				expectedFields int,
			) ([]string, error) {
				if expectedFields ==
					sorPostgreSQLDatabaseDefaultPrivilegeFieldCount {
					return nil,
						errors.New(
							"synthetic default ACL query failure",
						)
				}

				return testSORPostgreSQLDatabaseObserverExactQuery(
					t,
					policy,
					database,
					query,
					expectedFields,
					false,
				)
			},

			inspectPassfile: func(
				sorPostgreSQLDatabasePolicy,
			) (
				sorPostgreSQLDatabasePassfileFacts,
				string,
				error,
			) {
				inspectCalls++

				return testSORPostgreSQLDatabasePassfileExactFacts(),
					testSORPostgreSQLDatabaseSecret,
					nil
			},
		}

	observation,
		state,
		err :=
		observer.Observe(
			policy,
		)

	if err == nil {
		t.Fatal(
			"privilege observer failure was accepted",
		)
	}

	if state !=
		sorPostgreSQLDatabaseUnknown {
		t.Fatalf(
			"failure state = %s, want UNKNOWN",
			state,
		)
	}

	if inspectCalls != 0 {
		t.Fatalf(
			"credential/passfile observation ran after privilege failure: %d",
			inspectCalls,
		)
	}

	if observation.OwnerRole !=
		sorPostgreSQLDatabaseResourceOwnedMatch ||
		observation.IngestRole !=
			sorPostgreSQLDatabaseResourceOwnedMatch ||
		observation.Database !=
			sorPostgreSQLDatabaseResourceOwnedMatch ||
		observation.Schema !=
			sorPostgreSQLDatabaseResourceOwnedMatch ||
		observation.RelationalFoundation !=
			sorPostgreSQLDatabaseResourceOwnedMatch ||
		observation.Privileges !=
			sorPostgreSQLDatabaseResourceUnknown ||
		observation.Credential !=
			sorPostgreSQLDatabaseResourceUnknown ||
		observation.Passfile !=
			sorPostgreSQLDatabaseResourceUnknown {
		t.Fatalf(
			"unexpected partial observation after failure: %#v",
			observation,
		)
	}
}

func TestSORPostgreSQLDatabaseObserverCredentialFailureIsUnknown(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	observer :=
		sorPostgreSQLDatabaseObserver{
			query: func(
				database string,
				query string,
				expectedFields int,
			) ([]string, error) {
				if expectedFields ==
					sorPostgreSQLDatabaseCredentialFieldCount &&
					strings.Contains(
						query,
						"WITH target_role AS",
					) {
					return nil,
						errors.New(
							"synthetic credential query failure",
						)
				}

				return testSORPostgreSQLDatabaseObserverExactQuery(
					t,
					policy,
					database,
					query,
					expectedFields,
					false,
				)
			},

			inspectPassfile: func(
				sorPostgreSQLDatabasePolicy,
			) (
				sorPostgreSQLDatabasePassfileFacts,
				string,
				error,
			) {
				return testSORPostgreSQLDatabasePassfileExactFacts(),
					testSORPostgreSQLDatabaseSecret,
					nil
			},
		}

	_,
		state,
		err :=
		observer.Observe(
			policy,
		)

	if err == nil {
		t.Fatal(
			"credential observer failure was accepted",
		)
	}

	if state !=
		sorPostgreSQLDatabaseUnknown {
		t.Fatalf(
			"failure state = %s, want UNKNOWN",
			state,
		)
	}
}

func assertSORPostgreSQLDatabaseObserverAllResources(
	t *testing.T,
	observation sorPostgreSQLDatabaseObservation,
	expected sorPostgreSQLDatabaseResourceState,
) {
	t.Helper()

	resources :=
		[]struct {
			name  string
			state sorPostgreSQLDatabaseResourceState
		}{
			{
				name:  "owner role",
				state: observation.OwnerRole,
			},
			{
				name:  "ingest role",
				state: observation.IngestRole,
			},
			{
				name:  "database",
				state: observation.Database,
			},
			{
				name:  "schema",
				state: observation.Schema,
			},
			{
				name:  "relational foundation",
				state: observation.RelationalFoundation,
			},
			{
				name:  "privileges",
				state: observation.Privileges,
			},
			{
				name:  "credential",
				state: observation.Credential,
			},
			{
				name:  "passfile",
				state: observation.Passfile,
			},
		}

	for _, resource := range resources {
		if resource.state != expected {
			t.Fatalf(
				"%s state = %s, want %s",
				resource.name,
				resource.state,
				expected,
			)
		}
	}
}

func testSORPostgreSQLDatabaseObserverExactQuery(
	t *testing.T,
	policy sorPostgreSQLDatabasePolicy,
	database string,
	query string,
	expectedFields int,
	explicitDrift bool,
) ([]string, error) {
	t.Helper()

	switch {
	case database == "postgres" &&
		expectedFields ==
			sorPostgreSQLDatabaseCatalogRoleFieldCount &&
		strings.Contains(
			query,
			"rolname = 'fi_owner'",
		):

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
		expectedFields ==
			sorPostgreSQLDatabaseCatalogRoleFieldCount &&
		strings.Contains(
			query,
			"rolname = 'fi_ingest'",
		):

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
		expectedFields ==
			sorPostgreSQLDatabaseCatalogDatabaseFieldCount &&
		strings.Contains(
			query,
			"FROM pg_catalog.pg_database",
		):

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
		expectedFields ==
			sorPostgreSQLDatabaseCatalogSchemaFieldCount &&
		strings.Contains(
			query,
			"FROM pg_catalog.pg_namespace",
		):

		return []string{
				"t",
				policy.SchemaOwner,
				policy.SchemaComment,
			},
			nil

	case database == policy.DatabaseName &&
		expectedFields ==
			sorPostgreSQLDatabaseCatalogFoundationFieldCount &&
		strings.Contains(
			query,
			"information_schema.tables",
		):

		return []string{
				"49",
				"0",
				"0",
			},
			nil

	case database == policy.DatabaseName &&
		expectedFields ==
			sorPostgreSQLDatabaseExplicitPrivilegeFieldCount:

		fields :=
			testSORPostgreSQLDatabaseExplicitPrivilegeFields()

		if explicitDrift {
			fields[32] = "1"
		}

		return fields,
			nil

	case database == policy.DatabaseName &&
		expectedFields ==
			sorPostgreSQLDatabaseDefaultPrivilegeFieldCount:

		return testSORPostgreSQLDatabaseDefaultPrivilegeFields(),
			nil

	case database == "postgres" &&
		expectedFields ==
			sorPostgreSQLDatabaseCredentialFieldCount &&
		strings.Contains(
			query,
			"WITH target_role AS",
		):

		return []string{
				"t",
				testSORPostgreSQLDatabaseVerifier,
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
}
