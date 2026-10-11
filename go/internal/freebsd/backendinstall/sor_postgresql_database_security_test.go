// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import "testing"

func TestSORPostgreSQLDatabaseSecurityExactOwnedMatch(
	t *testing.T,
) {
	policy := testSORPostgreSQLDatabasePolicy(t)

	observation := classifySORPostgreSQLDatabaseCatalog(
		policy,
		testSORPostgreSQLDatabaseCatalogExactFacts(policy),
	)

	observation = completeSORPostgreSQLDatabaseObservation(
		observation,
		policy,
		testSORPostgreSQLDatabasePrivilegeExactFacts(policy),
		testSORPostgreSQLDatabaseCredentialExactFacts(),
		testSORPostgreSQLDatabasePassfileExactFacts(),
	)

	state := classifySORPostgreSQLDatabase(observation)
	if state != sorPostgreSQLDatabaseOwnedMatch {
		t.Fatalf(
			"database state = %s, want OWNED_MATCH",
			state,
		)
	}
}

func TestSORPostgreSQLDatabaseSecurityExactAbsent(
	t *testing.T,
) {
	policy := testSORPostgreSQLDatabasePolicy(t)

	observation := classifySORPostgreSQLDatabaseCatalog(
		policy,
		sorPostgreSQLDatabaseCatalogFacts{},
	)

	observation = completeSORPostgreSQLDatabaseObservation(
		observation,
		policy,
		sorPostgreSQLDatabasePrivilegeFacts{
			Observed: true,
		},
		sorPostgreSQLDatabaseCredentialFacts{
			Observed: true,
		},
		sorPostgreSQLDatabasePassfileFacts{
			Observed: true,
		},
	)

	state := classifySORPostgreSQLDatabase(observation)
	if state != sorPostgreSQLDatabaseAbsent {
		t.Fatalf(
			"database state = %s, want ABSENT",
			state,
		)
	}
}

func TestSORPostgreSQLDatabasePrivilegesRejectPublicDatabaseConnect(
	t *testing.T,
) {
	policy := testSORPostgreSQLDatabasePolicy(t)
	facts := testSORPostgreSQLDatabasePrivilegeExactFacts(policy)
	facts.PublicDatabaseConnect = true

	assertSORPostgreSQLDatabaseSecurityResource(
		t,
		classifySORPostgreSQLDatabasePrivileges(policy, facts),
		sorPostgreSQLDatabaseResourceOwnedDrift,
	)
}

func TestSORPostgreSQLDatabasePrivilegesRejectUpdateAuthority(
	t *testing.T,
) {
	policy := testSORPostgreSQLDatabasePolicy(t)
	facts := testSORPostgreSQLDatabasePrivilegeExactFacts(policy)
	facts.TableUpdateCount = 1

	assertSORPostgreSQLDatabaseSecurityResource(
		t,
		classifySORPostgreSQLDatabasePrivileges(policy, facts),
		sorPostgreSQLDatabaseResourceOwnedDrift,
	)
}

func TestSORPostgreSQLDatabasePrivilegesRejectDefaultPrivilegeDrift(
	t *testing.T,
) {
	policy := testSORPostgreSQLDatabasePolicy(t)
	facts := testSORPostgreSQLDatabasePrivilegeExactFacts(policy)
	facts.DefaultTableDelete = true

	assertSORPostgreSQLDatabaseSecurityResource(
		t,
		classifySORPostgreSQLDatabasePrivileges(policy, facts),
		sorPostgreSQLDatabaseResourceOwnedDrift,
	)
}

func TestSORPostgreSQLDatabaseCredentialRejectNonSCRAM(
	t *testing.T,
) {
	facts := testSORPostgreSQLDatabaseCredentialExactFacts()
	facts.SCRAMSHA256 = false

	assertSORPostgreSQLDatabaseSecurityResource(
		t,
		classifySORPostgreSQLDatabaseCredential(facts),
		sorPostgreSQLDatabaseResourceOwnedDrift,
	)
}

func TestSORPostgreSQLDatabaseCredentialRejectPassfileMismatch(
	t *testing.T,
) {
	facts := testSORPostgreSQLDatabaseCredentialExactFacts()
	facts.MatchesPassfile = false

	assertSORPostgreSQLDatabaseSecurityResource(
		t,
		classifySORPostgreSQLDatabaseCredential(facts),
		sorPostgreSQLDatabaseResourceOwnedDrift,
	)
}

func TestSORPostgreSQLDatabasePassfileRejectWrongMode(
	t *testing.T,
) {
	facts := testSORPostgreSQLDatabasePassfileExactFacts()
	facts.Mode = 0o640

	assertSORPostgreSQLDatabaseSecurityResource(
		t,
		classifySORPostgreSQLDatabasePassfile(facts),
		sorPostgreSQLDatabaseResourceOwnedDrift,
	)
}

func TestSORPostgreSQLDatabasePassfileRejectWrongOwner(
	t *testing.T,
) {
	facts := testSORPostgreSQLDatabasePassfileExactFacts()
	facts.UID = 0

	assertSORPostgreSQLDatabaseSecurityResource(
		t,
		classifySORPostgreSQLDatabasePassfile(facts),
		sorPostgreSQLDatabaseResourceOwnedDrift,
	)
}

func TestSORPostgreSQLDatabasePassfileRejectHardLink(
	t *testing.T,
) {
	facts := testSORPostgreSQLDatabasePassfileExactFacts()
	facts.LinkCount = 2

	assertSORPostgreSQLDatabaseSecurityResource(
		t,
		classifySORPostgreSQLDatabasePassfile(facts),
		sorPostgreSQLDatabaseResourceOwnedDrift,
	)
}

func TestSORPostgreSQLDatabaseSecurityUnobservedFailsUnknown(
	t *testing.T,
) {
	policy := testSORPostgreSQLDatabasePolicy(t)

	assertSORPostgreSQLDatabaseSecurityResource(
		t,
		classifySORPostgreSQLDatabasePrivileges(
			policy,
			sorPostgreSQLDatabasePrivilegeFacts{},
		),
		sorPostgreSQLDatabaseResourceUnknown,
	)

	assertSORPostgreSQLDatabaseSecurityResource(
		t,
		classifySORPostgreSQLDatabaseCredential(
			sorPostgreSQLDatabaseCredentialFacts{},
		),
		sorPostgreSQLDatabaseResourceUnknown,
	)

	assertSORPostgreSQLDatabaseSecurityResource(
		t,
		classifySORPostgreSQLDatabasePassfile(
			sorPostgreSQLDatabasePassfileFacts{},
		),
		sorPostgreSQLDatabaseResourceUnknown,
	)
}

func testSORPostgreSQLDatabasePrivilegeExactFacts(
	policy sorPostgreSQLDatabasePolicy,
) sorPostgreSQLDatabasePrivilegeFacts {
	const sequenceCount = 12

	return sorPostgreSQLDatabasePrivilegeFacts{
		Applicable: true,
		Observed:   true,

		DatabaseConnect:            true,
		DatabaseConnectGrantOption: false,
		DatabaseCreate:             false,
		DatabaseTemporary:          false,
		PublicDatabaseConnect:      false,
		PublicDatabaseCreate:       false,
		PublicDatabaseTemporary:    false,

		SchemaUsage:                     true,
		SchemaUsageGrantOption:          false,
		SchemaCreate:                    false,
		PublicSchemaUsage:               false,
		PublicSchemaCreate:              false,
		PublicDefaultSchemaCreate:       false,
		UnexpectedExplicitACLGrantCount: 0,
		UnexpectedDefaultACLGrantCount:  0,

		TableCount:                  policy.ExpectedRelationalTableCount,
		TableSelectCount:            policy.ExpectedRelationalTableCount,
		TableInsertCount:            policy.ExpectedRelationalTableCount,
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

		SequenceCount:                  sequenceCount,
		SequenceUsageCount:             sequenceCount,
		SequenceSelectCount:            sequenceCount,
		SequenceUsageGrantOptionCount:  0,
		SequenceSelectGrantOptionCount: 0,
		SequenceUpdateCount:            0,

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
	}
}

func testSORPostgreSQLDatabaseCredentialExactFacts() sorPostgreSQLDatabaseCredentialFacts {
	return sorPostgreSQLDatabaseCredentialFacts{
		MatchesPassfile: true,
		Observed:        true,
		PasswordPresent: true,
		RoleExists:      true,
		SCRAMSHA256:     true,
	}
}

func testSORPostgreSQLDatabasePassfileExactFacts() sorPostgreSQLDatabasePassfileFacts {
	return sorPostgreSQLDatabasePassfileFacts{
		Exists:        true,
		GID:           sorPostgreSQLDatabasePassfileGID,
		LinkCount:     1,
		Mode:          sorPostgreSQLDatabasePassfileMode,
		Observed:      true,
		PrefixMatches: true,
		Regular:       true,
		SecretValid:   true,
		UID:           sorPostgreSQLDatabasePassfileUID,
	}
}

func assertSORPostgreSQLDatabaseSecurityResource(
	t *testing.T,
	actual sorPostgreSQLDatabaseResourceState,
	expected sorPostgreSQLDatabaseResourceState,
) {
	t.Helper()

	if actual != expected {
		t.Fatalf(
			"resource state = %s, want %s",
			actual,
			expected,
		)
	}
}
