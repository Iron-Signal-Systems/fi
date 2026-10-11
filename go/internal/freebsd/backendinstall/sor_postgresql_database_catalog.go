// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import "strings"

type sorPostgreSQLDatabaseCatalogFacts struct {
	Database   sorPostgreSQLDatabaseCatalogDatabaseFacts
	Foundation sorPostgreSQLDatabaseCatalogFoundationFacts
	IngestRole sorPostgreSQLDatabaseCatalogRoleFacts
	OwnerRole  sorPostgreSQLDatabaseCatalogRoleFacts
	Schema     sorPostgreSQLDatabaseCatalogSchemaFacts
}

type sorPostgreSQLDatabaseCatalogDatabaseFacts struct {
	Collate  string
	Comment  string
	CType    string
	Encoding string
	Exists   bool
	Owner    string
}

type sorPostgreSQLDatabaseCatalogFoundationFacts struct {
	BadTypedColumns   int
	Exists            bool
	MissingCoreTables int
	SchemaComment     string
	TableCount        int
}

type sorPostgreSQLDatabaseCatalogRoleFacts struct {
	BypassRLS          bool
	CanLogin           bool
	Comment            string
	ConnectionLimit    int
	CreateDB           bool
	CreateRole         bool
	Exists             bool
	GrantedToCount     int
	Inherit            bool
	MemberOfCount      int
	PasswordPresent    bool
	Replication        bool
	Superuser          bool
	ValidUntilInfinity bool
}

type sorPostgreSQLDatabaseCatalogSchemaFacts struct {
	Comment string
	Exists  bool
	Owner   string
}

func classifySORPostgreSQLDatabaseCatalog(
	policy sorPostgreSQLDatabasePolicy,
	facts sorPostgreSQLDatabaseCatalogFacts,
) sorPostgreSQLDatabaseObservation {
	return sorPostgreSQLDatabaseObservation{
		OwnerRole: classifySORPostgreSQLDatabaseCatalogRole(
			policy.OwnerRole,
			facts.OwnerRole,
		),

		IngestRole: classifySORPostgreSQLDatabaseCatalogRole(
			policy.IngestRole,
			facts.IngestRole,
		),

		Database: classifySORPostgreSQLDatabaseCatalogDatabase(
			policy,
			facts.Database,
		),

		Schema: classifySORPostgreSQLDatabaseCatalogSchema(
			policy,
			facts.Schema,
		),

		RelationalFoundation: classifySORPostgreSQLDatabaseCatalogFoundation(
			policy,
			facts.Foundation,
		),

		// These remain UNKNOWN until their dedicated observers
		// are implemented. That intentionally prevents this
		// partial catalog observer from ever producing an
		// aggregate OWNED_MATCH.
		Privileges: sorPostgreSQLDatabaseResourceUnknown,

		Credential: sorPostgreSQLDatabaseResourceUnknown,

		Passfile: sorPostgreSQLDatabaseResourceUnknown,
	}
}

func classifySORPostgreSQLDatabaseCatalogDatabase(
	policy sorPostgreSQLDatabasePolicy,
	facts sorPostgreSQLDatabaseCatalogDatabaseFacts,
) sorPostgreSQLDatabaseResourceState {
	if !facts.Exists {
		return sorPostgreSQLDatabaseResourceAbsent
	}

	authority :=
		classifySORPostgreSQLDatabaseCatalogAuthority(
			facts.Comment,
			policy.DatabaseComment,
		)

	if authority !=
		sorPostgreSQLDatabaseResourceOwnedMatch {
		return authority
	}

	if facts.Owner !=
		policy.DatabaseOwner ||
		facts.Encoding !=
			policy.DatabaseEncoding ||
		facts.Collate !=
			policy.DatabaseCollate ||
		facts.CType !=
			policy.DatabaseCType {
		return sorPostgreSQLDatabaseResourceOwnedDrift
	}

	return sorPostgreSQLDatabaseResourceOwnedMatch
}

func classifySORPostgreSQLDatabaseCatalogFoundation(
	policy sorPostgreSQLDatabasePolicy,
	facts sorPostgreSQLDatabaseCatalogFoundationFacts,
) sorPostgreSQLDatabaseResourceState {
	if !facts.Exists {
		return sorPostgreSQLDatabaseResourceAbsent
	}

	authority :=
		classifySORPostgreSQLDatabaseCatalogAuthority(
			facts.SchemaComment,
			policy.SchemaComment,
		)

	if authority !=
		sorPostgreSQLDatabaseResourceOwnedMatch {
		return authority
	}

	if facts.TableCount !=
		policy.ExpectedRelationalTableCount ||
		facts.BadTypedColumns != 0 ||
		facts.MissingCoreTables != 0 {
		return sorPostgreSQLDatabaseResourceOwnedDrift
	}

	return sorPostgreSQLDatabaseResourceOwnedMatch
}

func classifySORPostgreSQLDatabaseCatalogRole(
	policy sorPostgreSQLDatabaseRolePolicy,
	facts sorPostgreSQLDatabaseCatalogRoleFacts,
) sorPostgreSQLDatabaseResourceState {
	if !facts.Exists {
		return sorPostgreSQLDatabaseResourceAbsent
	}

	authority :=
		classifySORPostgreSQLDatabaseCatalogAuthority(
			facts.Comment,
			policy.Comment,
		)

	if authority !=
		sorPostgreSQLDatabaseResourceOwnedMatch {
		return authority
	}

	if facts.BypassRLS !=
		policy.BypassRLS ||
		facts.CanLogin !=
			policy.CanLogin ||
		facts.ConnectionLimit !=
			policy.ConnectionLimit ||
		facts.CreateDB !=
			policy.CreateDB ||
		facts.CreateRole !=
			policy.CreateRole ||
		facts.GrantedToCount != 0 ||
		facts.Inherit !=
			policy.Inherit ||
		facts.MemberOfCount != 0 ||
		facts.PasswordPresent !=
			policy.PasswordRequired ||
		facts.Replication !=
			policy.Replication ||
		facts.Superuser !=
			policy.Superuser ||
		facts.ValidUntilInfinity !=
			policy.ValidUntilInfinity {
		return sorPostgreSQLDatabaseResourceOwnedDrift
	}

	return sorPostgreSQLDatabaseResourceOwnedMatch
}

func classifySORPostgreSQLDatabaseCatalogSchema(
	policy sorPostgreSQLDatabasePolicy,
	facts sorPostgreSQLDatabaseCatalogSchemaFacts,
) sorPostgreSQLDatabaseResourceState {
	if !facts.Exists {
		return sorPostgreSQLDatabaseResourceAbsent
	}

	authority :=
		classifySORPostgreSQLDatabaseCatalogAuthority(
			facts.Comment,
			policy.SchemaComment,
		)

	if authority !=
		sorPostgreSQLDatabaseResourceOwnedMatch {
		return authority
	}

	if facts.Owner !=
		policy.SchemaOwner {
		return sorPostgreSQLDatabaseResourceOwnedDrift
	}

	return sorPostgreSQLDatabaseResourceOwnedMatch
}

func classifySORPostgreSQLDatabaseCatalogAuthority(
	actual string,
	expected string,
) sorPostgreSQLDatabaseResourceState {
	if actual == expected {
		return sorPostgreSQLDatabaseResourceOwnedMatch
	}

	if strings.Contains(
		actual,
		"FI-MANAGED: ironsignal-fi-freebsd-sor-database-",
	) {
		return sorPostgreSQLDatabaseResourceOwnedDrift
	}

	return sorPostgreSQLDatabaseResourceForeignCollision
}
