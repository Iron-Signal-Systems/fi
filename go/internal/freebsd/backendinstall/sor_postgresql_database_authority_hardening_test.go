// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import "testing"

func TestSORPostgreSQLDatabaseAuthorityRolesRequireNoMemberships(
	t *testing.T,
) {
	policy := testSORPostgreSQLDatabasePolicy(t)

	facts :=
		testSORPostgreSQLDatabaseCatalogExactFacts(
			policy,
		)

	facts.IngestRole.MemberOfCount = 1

	observation :=
		classifySORPostgreSQLDatabaseCatalog(
			policy,
			facts,
		)

	if observation.IngestRole !=
		sorPostgreSQLDatabaseResourceOwnedDrift {
		t.Fatalf(
			"ingest role membership state = %s, want OWNED_DRIFT",
			observation.IngestRole,
		)
	}

	facts =
		testSORPostgreSQLDatabaseCatalogExactFacts(
			policy,
		)

	facts.OwnerRole.GrantedToCount = 1

	observation =
		classifySORPostgreSQLDatabaseCatalog(
			policy,
			facts,
		)

	if observation.OwnerRole !=
		sorPostgreSQLDatabaseResourceOwnedDrift {
		t.Fatalf(
			"owner role granted-to state = %s, want OWNED_DRIFT",
			observation.OwnerRole,
		)
	}
}

func TestSORPostgreSQLDatabaseAuthorityRolesRequirePasswordPolicy(
	t *testing.T,
) {
	policy := testSORPostgreSQLDatabasePolicy(t)

	facts :=
		testSORPostgreSQLDatabaseCatalogExactFacts(
			policy,
		)

	facts.OwnerRole.PasswordPresent = true

	observation :=
		classifySORPostgreSQLDatabaseCatalog(
			policy,
			facts,
		)

	if observation.OwnerRole !=
		sorPostgreSQLDatabaseResourceOwnedDrift {
		t.Fatalf(
			"owner role password state = %s, want OWNED_DRIFT",
			observation.OwnerRole,
		)
	}

	facts =
		testSORPostgreSQLDatabaseCatalogExactFacts(
			policy,
		)

	facts.IngestRole.PasswordPresent = false

	observation =
		classifySORPostgreSQLDatabaseCatalog(
			policy,
			facts,
		)

	if observation.IngestRole !=
		sorPostgreSQLDatabaseResourceOwnedDrift {
		t.Fatalf(
			"ingest role password state = %s, want OWNED_DRIFT",
			observation.IngestRole,
		)
	}
}

func TestSORPostgreSQLDatabaseAuthorityRolesRequireInfinitePasswordLifetime(
	t *testing.T,
) {
	policy := testSORPostgreSQLDatabasePolicy(t)

	if !policy.OwnerRole.ValidUntilInfinity ||
		!policy.IngestRole.ValidUntilInfinity {
		t.Fatal(
			"FI role policy must require VALID UNTIL infinity",
		)
	}

	facts :=
		testSORPostgreSQLDatabaseCatalogExactFacts(
			policy,
		)

	facts.IngestRole.ValidUntilInfinity = false

	observation :=
		classifySORPostgreSQLDatabaseCatalog(
			policy,
			facts,
		)

	if observation.IngestRole !=
		sorPostgreSQLDatabaseResourceOwnedDrift {
		t.Fatalf(
			"ingest password lifetime state = %s, want OWNED_DRIFT",
			observation.IngestRole,
		)
	}
}

func TestSORPostgreSQLDatabaseAuthorityRejectsDatabaseCreate(
	t *testing.T,
) {
	policy := testSORPostgreSQLDatabasePolicy(t)
	facts := testSORPostgreSQLDatabasePrivilegeExactFacts(policy)

	facts.DatabaseCreate = true

	state :=
		classifySORPostgreSQLDatabasePrivileges(
			policy,
			facts,
		)

	if state !=
		sorPostgreSQLDatabaseResourceOwnedDrift {
		t.Fatalf(
			"database CREATE privilege state = %s, want OWNED_DRIFT",
			state,
		)
	}
}

func TestSORPostgreSQLDatabaseAuthorityRejectsDatabaseTemporary(
	t *testing.T,
) {
	policy := testSORPostgreSQLDatabasePolicy(t)
	facts := testSORPostgreSQLDatabasePrivilegeExactFacts(policy)

	facts.DatabaseTemporary = true

	state :=
		classifySORPostgreSQLDatabasePrivileges(
			policy,
			facts,
		)

	if state !=
		sorPostgreSQLDatabaseResourceOwnedDrift {
		t.Fatalf(
			"database TEMP privilege state = %s, want OWNED_DRIFT",
			state,
		)
	}
}

func TestSORPostgreSQLDatabaseAuthorityRejectsPublicDatabaseAuthority(
	t *testing.T,
) {
	policy := testSORPostgreSQLDatabasePolicy(t)

	createFacts :=
		testSORPostgreSQLDatabasePrivilegeExactFacts(
			policy,
		)

	createFacts.PublicDatabaseCreate = true

	if state :=
		classifySORPostgreSQLDatabasePrivileges(
			policy,
			createFacts,
		); state !=
		sorPostgreSQLDatabaseResourceOwnedDrift {
		t.Fatalf(
			"PUBLIC database CREATE state = %s, want OWNED_DRIFT",
			state,
		)
	}

	temporaryFacts :=
		testSORPostgreSQLDatabasePrivilegeExactFacts(
			policy,
		)

	temporaryFacts.PublicDatabaseTemporary = true

	if state :=
		classifySORPostgreSQLDatabasePrivileges(
			policy,
			temporaryFacts,
		); state !=
		sorPostgreSQLDatabaseResourceOwnedDrift {
		t.Fatalf(
			"PUBLIC database TEMP state = %s, want OWNED_DRIFT",
			state,
		)
	}
}

func TestSORPostgreSQLDatabaseAuthorityRejectsTableReferences(
	t *testing.T,
) {
	policy := testSORPostgreSQLDatabasePolicy(t)
	facts := testSORPostgreSQLDatabasePrivilegeExactFacts(policy)

	facts.TableReferencesCount = 1

	state :=
		classifySORPostgreSQLDatabasePrivileges(
			policy,
			facts,
		)

	if state !=
		sorPostgreSQLDatabaseResourceOwnedDrift {
		t.Fatalf(
			"table REFERENCES privilege state = %s, want OWNED_DRIFT",
			state,
		)
	}
}

func TestSORPostgreSQLDatabaseAuthorityRejectsTableTrigger(
	t *testing.T,
) {
	policy := testSORPostgreSQLDatabasePolicy(t)
	facts := testSORPostgreSQLDatabasePrivilegeExactFacts(policy)

	facts.TableTriggerCount = 1

	state :=
		classifySORPostgreSQLDatabasePrivileges(
			policy,
			facts,
		)

	if state !=
		sorPostgreSQLDatabaseResourceOwnedDrift {
		t.Fatalf(
			"table TRIGGER privilege state = %s, want OWNED_DRIFT",
			state,
		)
	}
}

func TestSORPostgreSQLDatabaseAuthorityRejectsDefaultReferences(
	t *testing.T,
) {
	policy := testSORPostgreSQLDatabasePolicy(t)
	facts := testSORPostgreSQLDatabasePrivilegeExactFacts(policy)

	facts.DefaultTableReferences = true

	state :=
		classifySORPostgreSQLDatabasePrivileges(
			policy,
			facts,
		)

	if state !=
		sorPostgreSQLDatabaseResourceOwnedDrift {
		t.Fatalf(
			"default REFERENCES privilege state = %s, want OWNED_DRIFT",
			state,
		)
	}
}

func TestSORPostgreSQLDatabaseAuthorityRejectsDefaultTrigger(
	t *testing.T,
) {
	policy := testSORPostgreSQLDatabasePolicy(t)
	facts := testSORPostgreSQLDatabasePrivilegeExactFacts(policy)

	facts.DefaultTableTrigger = true

	state :=
		classifySORPostgreSQLDatabasePrivileges(
			policy,
			facts,
		)

	if state !=
		sorPostgreSQLDatabaseResourceOwnedDrift {
		t.Fatalf(
			"default TRIGGER privilege state = %s, want OWNED_DRIFT",
			state,
		)
	}
}

func TestSORPostgreSQLDatabaseAuthorityRejectsIngestSchemaCreate(
	t *testing.T,
) {
	policy := testSORPostgreSQLDatabasePolicy(t)

	facts :=
		testSORPostgreSQLDatabasePrivilegeExactFacts(
			policy,
		)

	facts.SchemaCreate = true

	state :=
		classifySORPostgreSQLDatabasePrivileges(
			policy,
			facts,
		)

	if state !=
		sorPostgreSQLDatabaseResourceOwnedDrift {
		t.Fatalf(
			"ingest schema CREATE state = %s, want OWNED_DRIFT",
			state,
		)
	}
}

func TestSORPostgreSQLDatabaseAuthorityRejectsPublicDefaultSchemaCreate(
	t *testing.T,
) {
	policy := testSORPostgreSQLDatabasePolicy(t)

	facts :=
		testSORPostgreSQLDatabasePrivilegeExactFacts(
			policy,
		)

	facts.PublicDefaultSchemaCreate = true

	state :=
		classifySORPostgreSQLDatabasePrivileges(
			policy,
			facts,
		)

	if state !=
		sorPostgreSQLDatabaseResourceOwnedDrift {
		t.Fatalf(
			"PUBLIC CREATE on schema public state = %s, want OWNED_DRIFT",
			state,
		)
	}
}

func TestSORPostgreSQLDatabaseAuthorityRejectsTableMaintain(
	t *testing.T,
) {
	policy := testSORPostgreSQLDatabasePolicy(t)
	facts := testSORPostgreSQLDatabasePrivilegeExactFacts(policy)

	facts.TableMaintainCount = 1

	state :=
		classifySORPostgreSQLDatabasePrivileges(
			policy,
			facts,
		)

	if state !=
		sorPostgreSQLDatabaseResourceOwnedDrift {
		t.Fatalf(
			"table MAINTAIN privilege state = %s, want OWNED_DRIFT",
			state,
		)
	}
}

func TestSORPostgreSQLDatabaseAuthorityRejectsColumnUpdate(
	t *testing.T,
) {
	policy := testSORPostgreSQLDatabasePolicy(t)
	facts := testSORPostgreSQLDatabasePrivilegeExactFacts(policy)

	facts.TableColumnUpdateCount = 1

	state :=
		classifySORPostgreSQLDatabasePrivileges(
			policy,
			facts,
		)

	if state !=
		sorPostgreSQLDatabaseResourceOwnedDrift {
		t.Fatalf(
			"column UPDATE privilege state = %s, want OWNED_DRIFT",
			state,
		)
	}
}

func TestSORPostgreSQLDatabaseAuthorityRejectsColumnReferences(
	t *testing.T,
) {
	policy := testSORPostgreSQLDatabasePolicy(t)
	facts := testSORPostgreSQLDatabasePrivilegeExactFacts(policy)

	facts.TableColumnReferencesCount = 1

	state :=
		classifySORPostgreSQLDatabasePrivileges(
			policy,
			facts,
		)

	if state !=
		sorPostgreSQLDatabaseResourceOwnedDrift {
		t.Fatalf(
			"column REFERENCES privilege state = %s, want OWNED_DRIFT",
			state,
		)
	}
}

func TestSORPostgreSQLDatabaseAuthorityRejectsDefaultMaintain(
	t *testing.T,
) {
	policy := testSORPostgreSQLDatabasePolicy(t)
	facts := testSORPostgreSQLDatabasePrivilegeExactFacts(policy)

	facts.DefaultTableMaintain = true

	state :=
		classifySORPostgreSQLDatabasePrivileges(
			policy,
			facts,
		)

	if state !=
		sorPostgreSQLDatabaseResourceOwnedDrift {
		t.Fatalf(
			"default MAINTAIN privilege state = %s, want OWNED_DRIFT",
			state,
		)
	}
}

func TestSORPostgreSQLDatabaseAuthorityRejectsDatabaseConnectGrantOption(
	t *testing.T,
) {
	policy := testSORPostgreSQLDatabasePolicy(t)
	facts := testSORPostgreSQLDatabasePrivilegeExactFacts(policy)

	facts.DatabaseConnectGrantOption = true

	state :=
		classifySORPostgreSQLDatabasePrivileges(
			policy,
			facts,
		)

	if state !=
		sorPostgreSQLDatabaseResourceOwnedDrift {
		t.Fatalf(
			"database CONNECT grant option state = %s, want OWNED_DRIFT",
			state,
		)
	}
}

func TestSORPostgreSQLDatabaseAuthorityRejectsSchemaUsageGrantOption(
	t *testing.T,
) {
	policy := testSORPostgreSQLDatabasePolicy(t)
	facts := testSORPostgreSQLDatabasePrivilegeExactFacts(policy)

	facts.SchemaUsageGrantOption = true

	state :=
		classifySORPostgreSQLDatabasePrivileges(
			policy,
			facts,
		)

	if state !=
		sorPostgreSQLDatabaseResourceOwnedDrift {
		t.Fatalf(
			"schema USAGE grant option state = %s, want OWNED_DRIFT",
			state,
		)
	}
}

func TestSORPostgreSQLDatabaseAuthorityRejectsTableSelectGrantOption(
	t *testing.T,
) {
	policy := testSORPostgreSQLDatabasePolicy(t)
	facts := testSORPostgreSQLDatabasePrivilegeExactFacts(policy)

	facts.TableSelectGrantOptionCount = 1

	state :=
		classifySORPostgreSQLDatabasePrivileges(
			policy,
			facts,
		)

	if state !=
		sorPostgreSQLDatabaseResourceOwnedDrift {
		t.Fatalf(
			"table SELECT grant option state = %s, want OWNED_DRIFT",
			state,
		)
	}
}

func TestSORPostgreSQLDatabaseAuthorityRejectsTableInsertGrantOption(
	t *testing.T,
) {
	policy := testSORPostgreSQLDatabasePolicy(t)
	facts := testSORPostgreSQLDatabasePrivilegeExactFacts(policy)

	facts.TableInsertGrantOptionCount = 1

	state :=
		classifySORPostgreSQLDatabasePrivileges(
			policy,
			facts,
		)

	if state !=
		sorPostgreSQLDatabaseResourceOwnedDrift {
		t.Fatalf(
			"table INSERT grant option state = %s, want OWNED_DRIFT",
			state,
		)
	}
}

func TestSORPostgreSQLDatabaseAuthorityRejectsSequenceUsageGrantOption(
	t *testing.T,
) {
	policy := testSORPostgreSQLDatabasePolicy(t)
	facts := testSORPostgreSQLDatabasePrivilegeExactFacts(policy)

	facts.SequenceUsageGrantOptionCount = 1

	state :=
		classifySORPostgreSQLDatabasePrivileges(
			policy,
			facts,
		)

	if state !=
		sorPostgreSQLDatabaseResourceOwnedDrift {
		t.Fatalf(
			"sequence USAGE grant option state = %s, want OWNED_DRIFT",
			state,
		)
	}
}

func TestSORPostgreSQLDatabaseAuthorityRejectsSequenceSelectGrantOption(
	t *testing.T,
) {
	policy := testSORPostgreSQLDatabasePolicy(t)
	facts := testSORPostgreSQLDatabasePrivilegeExactFacts(policy)

	facts.SequenceSelectGrantOptionCount = 1

	state :=
		classifySORPostgreSQLDatabasePrivileges(
			policy,
			facts,
		)

	if state !=
		sorPostgreSQLDatabaseResourceOwnedDrift {
		t.Fatalf(
			"sequence SELECT grant option state = %s, want OWNED_DRIFT",
			state,
		)
	}
}

func TestSORPostgreSQLDatabaseAuthorityRejectsDefaultTableGrantOptions(
	t *testing.T,
) {
	policy := testSORPostgreSQLDatabasePolicy(t)

	selectFacts :=
		testSORPostgreSQLDatabasePrivilegeExactFacts(
			policy,
		)

	selectFacts.DefaultTableSelectGrantOption = true

	if state :=
		classifySORPostgreSQLDatabasePrivileges(
			policy,
			selectFacts,
		); state !=
		sorPostgreSQLDatabaseResourceOwnedDrift {
		t.Fatalf(
			"default table SELECT grant option state = %s, want OWNED_DRIFT",
			state,
		)
	}

	insertFacts :=
		testSORPostgreSQLDatabasePrivilegeExactFacts(
			policy,
		)

	insertFacts.DefaultTableInsertGrantOption = true

	if state :=
		classifySORPostgreSQLDatabasePrivileges(
			policy,
			insertFacts,
		); state !=
		sorPostgreSQLDatabaseResourceOwnedDrift {
		t.Fatalf(
			"default table INSERT grant option state = %s, want OWNED_DRIFT",
			state,
		)
	}
}

func TestSORPostgreSQLDatabaseAuthorityRejectsDefaultSequenceGrantOptions(
	t *testing.T,
) {
	policy := testSORPostgreSQLDatabasePolicy(t)

	usageFacts :=
		testSORPostgreSQLDatabasePrivilegeExactFacts(
			policy,
		)

	usageFacts.DefaultSequenceUsageGrantOption = true

	if state :=
		classifySORPostgreSQLDatabasePrivileges(
			policy,
			usageFacts,
		); state !=
		sorPostgreSQLDatabaseResourceOwnedDrift {
		t.Fatalf(
			"default sequence USAGE grant option state = %s, want OWNED_DRIFT",
			state,
		)
	}

	selectFacts :=
		testSORPostgreSQLDatabasePrivilegeExactFacts(
			policy,
		)

	selectFacts.DefaultSequenceSelectGrantOption = true

	if state :=
		classifySORPostgreSQLDatabasePrivileges(
			policy,
			selectFacts,
		); state !=
		sorPostgreSQLDatabaseResourceOwnedDrift {
		t.Fatalf(
			"default sequence SELECT grant option state = %s, want OWNED_DRIFT",
			state,
		)
	}
}

func TestSORPostgreSQLDatabaseAuthorityRejectsUnexpectedExplicitACLGrant(
	t *testing.T,
) {
	policy := testSORPostgreSQLDatabasePolicy(t)

	facts :=
		testSORPostgreSQLDatabasePrivilegeExactFacts(
			policy,
		)

	facts.UnexpectedExplicitACLGrantCount = 1

	state :=
		classifySORPostgreSQLDatabasePrivileges(
			policy,
			facts,
		)

	if state !=
		sorPostgreSQLDatabaseResourceOwnedDrift {
		t.Fatalf(
			"unexpected explicit ACL grant state = %s, want OWNED_DRIFT",
			state,
		)
	}
}

func TestSORPostgreSQLDatabaseAuthorityRejectsUnexpectedDefaultACLGrant(
	t *testing.T,
) {
	policy := testSORPostgreSQLDatabasePolicy(t)

	facts :=
		testSORPostgreSQLDatabasePrivilegeExactFacts(
			policy,
		)

	facts.UnexpectedDefaultACLGrantCount = 1

	state :=
		classifySORPostgreSQLDatabasePrivileges(
			policy,
			facts,
		)

	if state !=
		sorPostgreSQLDatabaseResourceOwnedDrift {
		t.Fatalf(
			"unexpected default ACL grant state = %s, want OWNED_DRIFT",
			state,
		)
	}
}
