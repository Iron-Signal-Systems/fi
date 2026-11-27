// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"errors"
	"strings"
	"testing"
)

func TestSORPostgreSQLDatabaseCredentialObserverExactMatch(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	catalog :=
		testSORPostgreSQLDatabaseCredentialCatalogFacts(
			true,
			true,
		)

	queryCalls := 0
	inspectCalls := 0

	credential,
		passfile,
		err :=
		observeSORPostgreSQLDatabaseCredentialAndPassfile(
			func(
				database string,
				query string,
				expectedFields int,
			) ([]string, error) {
				queryCalls++

				if database != "postgres" {
					t.Fatalf(
						"database = %q, want postgres",
						database,
					)
				}

				if expectedFields !=
					sorPostgreSQLDatabaseCredentialFieldCount {
					t.Fatalf(
						"expectedFields = %d, want %d",
						expectedFields,
						sorPostgreSQLDatabaseCredentialFieldCount,
					)
				}

				if !strings.Contains(
					query,
					"pg_catalog.pg_authid",
				) ||
					!strings.Contains(
						query,
						"rolpassword",
					) {
					t.Fatal(
						"credential query missing pg_authid rolpassword authority",
					)
				}

				return []string{
						"t",
						testSORPostgreSQLDatabaseVerifier,
					},
					nil
			},
			func(
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
			policy,
			catalog,
		)
	if err != nil {
		t.Fatalf(
			"observe exact credential: %v",
			err,
		)
	}

	if queryCalls != 1 {
		t.Fatalf(
			"query calls = %d, want 1",
			queryCalls,
		)
	}

	if inspectCalls != 1 {
		t.Fatalf(
			"inspect calls = %d, want 1",
			inspectCalls,
		)
	}

	expectedCredential :=
		testSORPostgreSQLDatabaseCredentialExactFacts()

	if credential !=
		expectedCredential {
		t.Fatalf(
			"credential facts = %+v, want %+v",
			credential,
			expectedCredential,
		)
	}

	expectedPassfile :=
		testSORPostgreSQLDatabasePassfileExactFacts()

	if passfile !=
		expectedPassfile {
		t.Fatalf(
			"passfile facts = %+v, want %+v",
			passfile,
			expectedPassfile,
		)
	}

	state :=
		classifySORPostgreSQLDatabaseCredential(
			credential,
		)

	if state !=
		sorPostgreSQLDatabaseResourceOwnedMatch {
		t.Fatalf(
			"credential state = %s, want OWNED_MATCH",
			state,
		)
	}
}

func TestSORPostgreSQLDatabaseCredentialObserverWrongPassfileSecretDrifts(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	catalog :=
		testSORPostgreSQLDatabaseCredentialCatalogFacts(
			true,
			true,
		)

	wrongSecret :=
		"1123456789abcdef0123456789abcdef" +
			"0123456789abcdef0123456789abcdef"

	credential,
		_,
		err :=
		observeSORPostgreSQLDatabaseCredentialAndPassfile(
			func(
				string,
				string,
				int,
			) ([]string, error) {
				return []string{
						"t",
						testSORPostgreSQLDatabaseVerifier,
					},
					nil
			},
			func(
				sorPostgreSQLDatabasePolicy,
			) (
				sorPostgreSQLDatabasePassfileFacts,
				string,
				error,
			) {
				return testSORPostgreSQLDatabasePassfileExactFacts(),
					wrongSecret,
					nil
			},
			policy,
			catalog,
		)
	if err != nil {
		t.Fatalf(
			"observe wrong-secret credential: %v",
			err,
		)
	}

	if !credential.SCRAMSHA256 {
		t.Fatal(
			"valid SCRAM verifier was not recognized",
		)
	}

	if credential.MatchesPassfile {
		t.Fatal(
			"wrong passfile secret matched verifier",
		)
	}

	state :=
		classifySORPostgreSQLDatabaseCredential(
			credential,
		)

	if state !=
		sorPostgreSQLDatabaseResourceOwnedDrift {
		t.Fatalf(
			"wrong-secret credential state = %s, want OWNED_DRIFT",
			state,
		)
	}
}

func TestSORPostgreSQLDatabaseCredentialObserverMalformedVerifierDrifts(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	catalog :=
		testSORPostgreSQLDatabaseCredentialCatalogFacts(
			true,
			true,
		)

	credential,
		_,
		err :=
		observeSORPostgreSQLDatabaseCredentialAndPassfile(
			func(
				string,
				string,
				int,
			) ([]string, error) {
				return []string{
						"t",
						"not-a-scram-verifier",
					},
					nil
			},
			func(
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
			policy,
			catalog,
		)
	if err != nil {
		t.Fatalf(
			"observe malformed verifier: %v",
			err,
		)
	}

	if !credential.PasswordPresent {
		t.Fatal(
			"malformed non-empty verifier was not recorded as password present",
		)
	}

	if credential.SCRAMSHA256 {
		t.Fatal(
			"malformed verifier was accepted as SCRAM-SHA-256",
		)
	}

	if credential.MatchesPassfile {
		t.Fatal(
			"malformed verifier matched passfile",
		)
	}

	state :=
		classifySORPostgreSQLDatabaseCredential(
			credential,
		)

	if state !=
		sorPostgreSQLDatabaseResourceOwnedDrift {
		t.Fatalf(
			"malformed verifier state = %s, want OWNED_DRIFT",
			state,
		)
	}
}

func TestSORPostgreSQLDatabaseCredentialObserverAbsentRole(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	catalog :=
		testSORPostgreSQLDatabaseCredentialCatalogFacts(
			false,
			false,
		)

	credential,
		passfile,
		err :=
		observeSORPostgreSQLDatabaseCredentialAndPassfile(
			func(
				string,
				string,
				int,
			) ([]string, error) {
				return []string{
						"f",
						"",
					},
					nil
			},
			func(
				sorPostgreSQLDatabasePolicy,
			) (
				sorPostgreSQLDatabasePassfileFacts,
				string,
				error,
			) {
				return sorPostgreSQLDatabasePassfileFacts{
						Observed: true,
					},
					"",
					nil
			},
			policy,
			catalog,
		)
	if err != nil {
		t.Fatalf(
			"observe absent role: %v",
			err,
		)
	}

	if !credential.Observed {
		t.Fatal(
			"absent credential was not observed",
		)
	}

	if credential.RoleExists ||
		credential.PasswordPresent ||
		credential.SCRAMSHA256 ||
		credential.MatchesPassfile {
		t.Fatalf(
			"absent role produced credential authority: %+v",
			credential,
		)
	}

	if !passfile.Observed ||
		passfile.Exists {
		t.Fatalf(
			"unexpected absent passfile facts: %+v",
			passfile,
		)
	}

	state :=
		classifySORPostgreSQLDatabaseCredential(
			credential,
		)

	if state !=
		sorPostgreSQLDatabaseResourceAbsent {
		t.Fatalf(
			"absent credential state = %s, want ABSENT",
			state,
		)
	}
}

func TestSORPostgreSQLDatabaseCredentialObserverDetectsCatalogRace(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	catalog :=
		testSORPostgreSQLDatabaseCredentialCatalogFacts(
			true,
			true,
		)

	inspectCalls := 0

	credential,
		passfile,
		err :=
		observeSORPostgreSQLDatabaseCredentialAndPassfile(
			func(
				string,
				string,
				int,
			) ([]string, error) {
				return []string{
						"f",
						"",
					},
					nil
			},
			func(
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
			policy,
			catalog,
		)

	if err == nil {
		t.Fatal(
			"catalog/credential role race was accepted",
		)
	}

	if inspectCalls != 0 {
		t.Fatalf(
			"passfile inspected after catalog race: %d calls",
			inspectCalls,
		)
	}

	if credential.Observed ||
		passfile.Observed {
		t.Fatalf(
			"catalog race published observations: credential=%+v passfile=%+v",
			credential,
			passfile,
		)
	}
}

func TestSORPostgreSQLDatabaseCredentialObserverDetectsPasswordRace(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	catalog :=
		testSORPostgreSQLDatabaseCredentialCatalogFacts(
			true,
			true,
		)

	inspectCalls := 0

	_, _, err :=
		observeSORPostgreSQLDatabaseCredentialAndPassfile(
			func(
				string,
				string,
				int,
			) ([]string, error) {
				return []string{
						"t",
						"",
					},
					nil
			},
			func(
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
			policy,
			catalog,
		)

	if err == nil {
		t.Fatal(
			"catalog/credential password race was accepted",
		)
	}

	if inspectCalls != 0 {
		t.Fatalf(
			"passfile inspected after password race: %d calls",
			inspectCalls,
		)
	}
}

func TestSORPostgreSQLDatabaseCredentialObserverInspectorFailureDoesNotPublish(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	catalog :=
		testSORPostgreSQLDatabaseCredentialCatalogFacts(
			true,
			true,
		)

	credential,
		passfile,
		err :=
		observeSORPostgreSQLDatabaseCredentialAndPassfile(
			func(
				string,
				string,
				int,
			) ([]string, error) {
				return []string{
						"t",
						testSORPostgreSQLDatabaseVerifier,
					},
					nil
			},
			func(
				sorPostgreSQLDatabasePolicy,
			) (
				sorPostgreSQLDatabasePassfileFacts,
				string,
				error,
			) {
				return sorPostgreSQLDatabasePassfileFacts{},
					"",
					errors.New(
						"synthetic passfile failure",
					)
			},
			policy,
			catalog,
		)

	if err == nil {
		t.Fatal(
			"passfile inspection failure was accepted",
		)
	}

	if credential.Observed ||
		passfile.Observed {
		t.Fatalf(
			"inspection failure published observations: credential=%+v passfile=%+v",
			credential,
			passfile,
		)
	}

	if strings.Contains(
		err.Error(),
		testSORPostgreSQLDatabaseVerifier,
	) ||
		strings.Contains(
			err.Error(),
			testSORPostgreSQLDatabaseSecret,
		) {
		t.Fatal(
			"credential observer error disclosed credential material",
		)
	}
}

func TestSORPostgreSQLDatabaseCredentialObserverQueryFailureDoesNotPublish(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	catalog :=
		testSORPostgreSQLDatabaseCredentialCatalogFacts(
			true,
			true,
		)

	inspectCalls := 0

	credential,
		passfile,
		err :=
		observeSORPostgreSQLDatabaseCredentialAndPassfile(
			func(
				string,
				string,
				int,
			) ([]string, error) {
				return nil,
					errors.New(
						"synthetic protected query failure",
					)
			},
			func(
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
			policy,
			catalog,
		)

	if err == nil {
		t.Fatal(
			"credential query failure was accepted",
		)
	}

	if inspectCalls != 0 {
		t.Fatalf(
			"passfile inspected after query failure: %d calls",
			inspectCalls,
		)
	}

	if credential.Observed ||
		passfile.Observed {
		t.Fatalf(
			"query failure published observations: credential=%+v passfile=%+v",
			credential,
			passfile,
		)
	}
}

func TestSORPostgreSQLDatabaseCredentialObserverRejectsBadRoleBoolean(
	t *testing.T,
) {
	_, _, err :=
		parseSORPostgreSQLDatabaseCredentialFields(
			[]string{
				"bad",
				"",
			},
		)

	if err == nil {
		t.Fatal(
			"invalid role existence boolean was accepted",
		)
	}
}

func TestSORPostgreSQLDatabaseCredentialObserverRejectsAbsentRoleVerifier(
	t *testing.T,
) {
	_, _, err :=
		parseSORPostgreSQLDatabaseCredentialFields(
			[]string{
				"f",
				"unexpected-credential-data",
			},
		)

	if err == nil {
		t.Fatal(
			"absent role with verifier data was accepted",
		)
	}
}

func TestSORPostgreSQLDatabaseCredentialObserverRejectsWrongFieldCount(
	t *testing.T,
) {
	_, _, err :=
		parseSORPostgreSQLDatabaseCredentialFields(
			[]string{
				"t",
			},
		)

	if err == nil {
		t.Fatal(
			"short credential result was accepted",
		)
	}
}

func TestSORPostgreSQLDatabaseCredentialObserverQuotesRole(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	policy.IngestRole.Name =
		"fi'ingest"

	query :=
		buildSORPostgreSQLDatabaseCredentialQuery(
			policy,
		)

	if !strings.Contains(
		query,
		"'fi''ingest'",
	) {
		t.Fatal(
			"credential query did not quote ingest role",
		)
	}
}

func testSORPostgreSQLDatabaseCredentialCatalogFacts(
	exists bool,
	passwordPresent bool,
) sorPostgreSQLDatabaseCatalogFacts {
	return sorPostgreSQLDatabaseCatalogFacts{
		IngestRole: sorPostgreSQLDatabaseCatalogRoleFacts{
			Exists:          exists,
			PasswordPresent: passwordPresent,
		},
	}
}
