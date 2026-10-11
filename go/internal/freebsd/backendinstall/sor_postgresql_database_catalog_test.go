// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import "testing"

func TestSORPostgreSQLDatabaseCatalogAbsent(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	observation :=
		classifySORPostgreSQLDatabaseCatalog(
			policy,
			sorPostgreSQLDatabaseCatalogFacts{},
		)

	assertSORPostgreSQLDatabaseCatalogResource(
		t,
		"owner-role",
		observation.OwnerRole,
		sorPostgreSQLDatabaseResourceAbsent,
	)

	assertSORPostgreSQLDatabaseCatalogResource(
		t,
		"ingest-role",
		observation.IngestRole,
		sorPostgreSQLDatabaseResourceAbsent,
	)

	assertSORPostgreSQLDatabaseCatalogResource(
		t,
		"database",
		observation.Database,
		sorPostgreSQLDatabaseResourceAbsent,
	)

	assertSORPostgreSQLDatabaseCatalogResource(
		t,
		"schema",
		observation.Schema,
		sorPostgreSQLDatabaseResourceAbsent,
	)

	assertSORPostgreSQLDatabaseCatalogResource(
		t,
		"foundation",
		observation.RelationalFoundation,
		sorPostgreSQLDatabaseResourceAbsent,
	)

	if state :=
		classifySORPostgreSQLDatabase(
			observation,
		); state !=
		sorPostgreSQLDatabaseUnknown {
		t.Fatalf(
			"partial observer aggregate = %s, want UNKNOWN",
			state,
		)
	}
}

func TestSORPostgreSQLDatabaseCatalogExactKnownResources(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	observation :=
		classifySORPostgreSQLDatabaseCatalog(
			policy,
			testSORPostgreSQLDatabaseCatalogExactFacts(
				policy,
			),
		)

	resources := []struct {
		Name  string
		State sorPostgreSQLDatabaseResourceState
	}{
		{
			Name:  "owner-role",
			State: observation.OwnerRole,
		},
		{
			Name:  "ingest-role",
			State: observation.IngestRole,
		},
		{
			Name:  "database",
			State: observation.Database,
		},
		{
			Name:  "schema",
			State: observation.Schema,
		},
		{
			Name:  "foundation",
			State: observation.RelationalFoundation,
		},
	}

	for _, resource := range resources {
		assertSORPostgreSQLDatabaseCatalogResource(
			t,
			resource.Name,
			resource.State,
			sorPostgreSQLDatabaseResourceOwnedMatch,
		)
	}

	if observation.Privileges !=
		sorPostgreSQLDatabaseResourceUnknown ||
		observation.Credential !=
			sorPostgreSQLDatabaseResourceUnknown ||
		observation.Passfile !=
			sorPostgreSQLDatabaseResourceUnknown {
		t.Fatalf(
			"unimplemented resources must remain UNKNOWN: %+v",
			observation,
		)
	}

	if state :=
		classifySORPostgreSQLDatabase(
			observation,
		); state !=
		sorPostgreSQLDatabaseUnknown {
		t.Fatalf(
			"partial exact catalog aggregate = %s, want UNKNOWN",
			state,
		)
	}
}

func TestSORPostgreSQLDatabaseCatalogForeignRoleCollision(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	facts :=
		testSORPostgreSQLDatabaseCatalogExactFacts(
			policy,
		)

	facts.OwnerRole.Comment =
		"operator-owned role"

	observation :=
		classifySORPostgreSQLDatabaseCatalog(
			policy,
			facts,
		)

	assertSORPostgreSQLDatabaseCatalogResource(
		t,
		"owner-role",
		observation.OwnerRole,
		sorPostgreSQLDatabaseResourceForeignCollision,
	)
}

func TestSORPostgreSQLDatabaseCatalogOwnedRoleDrift(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	facts :=
		testSORPostgreSQLDatabaseCatalogExactFacts(
			policy,
		)

	facts.IngestRole.Superuser =
		true

	observation :=
		classifySORPostgreSQLDatabaseCatalog(
			policy,
			facts,
		)

	assertSORPostgreSQLDatabaseCatalogResource(
		t,
		"ingest-role",
		observation.IngestRole,
		sorPostgreSQLDatabaseResourceOwnedDrift,
	)
}

func TestSORPostgreSQLDatabaseCatalogDatabaseDrift(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	facts :=
		testSORPostgreSQLDatabaseCatalogExactFacts(
			policy,
		)

	facts.Database.Encoding =
		"SQL_ASCII"

	observation :=
		classifySORPostgreSQLDatabaseCatalog(
			policy,
			facts,
		)

	assertSORPostgreSQLDatabaseCatalogResource(
		t,
		"database",
		observation.Database,
		sorPostgreSQLDatabaseResourceOwnedDrift,
	)
}

func TestSORPostgreSQLDatabaseCatalogForeignSchemaCollision(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	facts :=
		testSORPostgreSQLDatabaseCatalogExactFacts(
			policy,
		)

	facts.Schema.Comment =
		"pre-existing schema"

	observation :=
		classifySORPostgreSQLDatabaseCatalog(
			policy,
			facts,
		)

	assertSORPostgreSQLDatabaseCatalogResource(
		t,
		"schema",
		observation.Schema,
		sorPostgreSQLDatabaseResourceForeignCollision,
	)
}

func TestSORPostgreSQLDatabaseCatalogFoundationTableCountDrift(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	facts :=
		testSORPostgreSQLDatabaseCatalogExactFacts(
			policy,
		)

	facts.Foundation.TableCount =
		policy.ExpectedRelationalTableCount - 1

	observation :=
		classifySORPostgreSQLDatabaseCatalog(
			policy,
			facts,
		)

	assertSORPostgreSQLDatabaseCatalogResource(
		t,
		"foundation",
		observation.RelationalFoundation,
		sorPostgreSQLDatabaseResourceOwnedDrift,
	)
}

func TestSORPostgreSQLDatabaseCatalogFoundationRejectsBadTypes(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	facts :=
		testSORPostgreSQLDatabaseCatalogExactFacts(
			policy,
		)

	facts.Foundation.BadTypedColumns =
		1

	observation :=
		classifySORPostgreSQLDatabaseCatalog(
			policy,
			facts,
		)

	assertSORPostgreSQLDatabaseCatalogResource(
		t,
		"foundation",
		observation.RelationalFoundation,
		sorPostgreSQLDatabaseResourceOwnedDrift,
	)
}

func TestSORPostgreSQLDatabaseCatalogFoundationRejectsMissingCore(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	facts :=
		testSORPostgreSQLDatabaseCatalogExactFacts(
			policy,
		)

	facts.Foundation.MissingCoreTables =
		1

	observation :=
		classifySORPostgreSQLDatabaseCatalog(
			policy,
			facts,
		)

	assertSORPostgreSQLDatabaseCatalogResource(
		t,
		"foundation",
		observation.RelationalFoundation,
		sorPostgreSQLDatabaseResourceOwnedDrift,
	)
}

func TestSORPostgreSQLDatabaseCatalogOwnedAuthorityDrift(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	facts :=
		testSORPostgreSQLDatabaseCatalogExactFacts(
			policy,
		)

	facts.Database.Comment =
		sorPostgreSQLDatabaseAuthorityMarker +
			"\nFI-ROLE: wrong-role"

	observation :=
		classifySORPostgreSQLDatabaseCatalog(
			policy,
			facts,
		)

	assertSORPostgreSQLDatabaseCatalogResource(
		t,
		"database",
		observation.Database,
		sorPostgreSQLDatabaseResourceOwnedDrift,
	)
}

func assertSORPostgreSQLDatabaseCatalogResource(
	t *testing.T,
	name string,
	actual sorPostgreSQLDatabaseResourceState,
	expected sorPostgreSQLDatabaseResourceState,
) {
	t.Helper()

	if actual != expected {
		t.Fatalf(
			"%s = %s, want %s",
			name,
			actual,
			expected,
		)
	}
}

func testSORPostgreSQLDatabaseCatalogExactFacts(
	policy sorPostgreSQLDatabasePolicy,
) sorPostgreSQLDatabaseCatalogFacts {
	return sorPostgreSQLDatabaseCatalogFacts{
		OwnerRole: sorPostgreSQLDatabaseCatalogRoleFacts{
			BypassRLS: policy.OwnerRole.BypassRLS,

			CanLogin: policy.OwnerRole.CanLogin,

			Comment: policy.OwnerRole.Comment,

			ConnectionLimit: policy.OwnerRole.ConnectionLimit,

			CreateDB: policy.OwnerRole.CreateDB,

			CreateRole: policy.OwnerRole.CreateRole,

			Exists: true,

			GrantedToCount: 0,

			Inherit: policy.OwnerRole.Inherit,

			MemberOfCount: 0,

			PasswordPresent: policy.OwnerRole.PasswordRequired,

			Replication: policy.OwnerRole.Replication,

			Superuser: policy.OwnerRole.Superuser,

			ValidUntilInfinity: policy.OwnerRole.ValidUntilInfinity,
		},

		IngestRole: sorPostgreSQLDatabaseCatalogRoleFacts{
			BypassRLS: policy.IngestRole.BypassRLS,

			CanLogin: policy.IngestRole.CanLogin,

			Comment: policy.IngestRole.Comment,

			ConnectionLimit: policy.IngestRole.ConnectionLimit,

			CreateDB: policy.IngestRole.CreateDB,

			CreateRole: policy.IngestRole.CreateRole,

			Exists: true,

			GrantedToCount: 0,

			Inherit: policy.IngestRole.Inherit,

			MemberOfCount: 0,

			PasswordPresent: policy.IngestRole.PasswordRequired,

			Replication: policy.IngestRole.Replication,

			Superuser: policy.IngestRole.Superuser,

			ValidUntilInfinity: policy.IngestRole.ValidUntilInfinity,
		},

		Database: sorPostgreSQLDatabaseCatalogDatabaseFacts{
			Collate: policy.DatabaseCollate,

			Comment: policy.DatabaseComment,

			CType: policy.DatabaseCType,

			Encoding: policy.DatabaseEncoding,

			Exists: true,

			Owner: policy.DatabaseOwner,
		},

		Schema: sorPostgreSQLDatabaseCatalogSchemaFacts{
			Comment: policy.SchemaComment,

			Exists: true,

			Owner: policy.SchemaOwner,
		},

		Foundation: sorPostgreSQLDatabaseCatalogFoundationFacts{
			BadTypedColumns: 0,

			Exists: true,

			MissingCoreTables: 0,

			SchemaComment: policy.SchemaComment,

			TableCount: policy.ExpectedRelationalTableCount,
		},
	}
}
