// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

const (
	sorPostgreSQLDatabasePassfileUID  uint64 = 4100
	sorPostgreSQLDatabasePassfileGID  uint64 = 4100
	sorPostgreSQLDatabasePassfileMode uint32 = 0o600
)

type sorPostgreSQLDatabasePrivilegeFacts struct {
	Applicable bool
	Observed   bool

	DatabaseConnect            bool
	DatabaseConnectGrantOption bool
	DatabaseCreate             bool
	DatabaseTemporary          bool
	PublicDatabaseConnect      bool
	PublicDatabaseCreate       bool
	PublicDatabaseTemporary    bool

	SchemaUsage                     bool
	SchemaUsageGrantOption          bool
	SchemaCreate                    bool
	PublicSchemaUsage               bool
	PublicSchemaCreate              bool
	PublicDefaultSchemaCreate       bool
	UnexpectedExplicitACLGrantCount int
	UnexpectedDefaultACLGrantCount  int

	TableCount                  int
	TableSelectCount            int
	TableInsertCount            int
	TableSelectGrantOptionCount int
	TableInsertGrantOptionCount int
	TableUpdateCount            int
	TableDeleteCount            int
	TableTruncateCount          int
	TableReferencesCount        int
	TableTriggerCount           int
	TableMaintainCount          int
	TableColumnUpdateCount      int
	TableColumnReferencesCount  int

	SequenceCount                  int
	SequenceUsageCount             int
	SequenceSelectCount            int
	SequenceUsageGrantOptionCount  int
	SequenceSelectGrantOptionCount int
	SequenceUpdateCount            int

	DefaultTableSelect            bool
	DefaultTableInsert            bool
	DefaultTableSelectGrantOption bool
	DefaultTableInsertGrantOption bool
	DefaultTableUpdate            bool
	DefaultTableDelete            bool
	DefaultTableTruncate          bool
	DefaultTableReferences        bool
	DefaultTableTrigger           bool
	DefaultTableMaintain          bool

	DefaultSequenceUsage             bool
	DefaultSequenceSelect            bool
	DefaultSequenceUsageGrantOption  bool
	DefaultSequenceSelectGrantOption bool
	DefaultSequenceUpdate            bool
}

type sorPostgreSQLDatabaseCredentialFacts struct {
	MatchesPassfile bool
	Observed        bool
	PasswordPresent bool
	RoleExists      bool
	SCRAMSHA256     bool
}

type sorPostgreSQLDatabasePassfileFacts struct {
	Exists        bool
	GID           uint64
	LinkCount     uint64
	Mode          uint32
	Observed      bool
	PrefixMatches bool
	Regular       bool
	SecretValid   bool
	UID           uint64
}

func completeSORPostgreSQLDatabaseObservation(
	observation sorPostgreSQLDatabaseObservation,
	policy sorPostgreSQLDatabasePolicy,
	privileges sorPostgreSQLDatabasePrivilegeFacts,
	credential sorPostgreSQLDatabaseCredentialFacts,
	passfile sorPostgreSQLDatabasePassfileFacts,
) sorPostgreSQLDatabaseObservation {
	observation.Privileges = classifySORPostgreSQLDatabasePrivileges(
		policy,
		privileges,
	)

	observation.Credential = classifySORPostgreSQLDatabaseCredential(
		credential,
	)

	observation.Passfile = classifySORPostgreSQLDatabasePassfile(
		passfile,
	)

	return observation
}

func classifySORPostgreSQLDatabasePrivileges(
	policy sorPostgreSQLDatabasePolicy,
	facts sorPostgreSQLDatabasePrivilegeFacts,
) sorPostgreSQLDatabaseResourceState {
	if !facts.Observed {
		return sorPostgreSQLDatabaseResourceUnknown
	}

	if !facts.Applicable {
		return sorPostgreSQLDatabaseResourceAbsent
	}

	if facts.UnexpectedExplicitACLGrantCount != 0 ||
		facts.UnexpectedDefaultACLGrantCount != 0 {
		return sorPostgreSQLDatabaseResourceOwnedDrift
	}

	if !facts.DatabaseConnect ||
		facts.DatabaseConnectGrantOption ||
		facts.DatabaseCreate ||
		facts.DatabaseTemporary ||
		facts.PublicDatabaseConnect ||
		facts.PublicDatabaseCreate ||
		facts.PublicDatabaseTemporary ||
		!facts.SchemaUsage ||
		facts.SchemaUsageGrantOption ||
		facts.SchemaCreate ||
		facts.PublicSchemaUsage ||
		facts.PublicSchemaCreate ||
		facts.PublicDefaultSchemaCreate {
		return sorPostgreSQLDatabaseResourceOwnedDrift
	}

	if facts.TableCount != policy.ExpectedRelationalTableCount ||
		facts.TableSelectCount != facts.TableCount ||
		facts.TableInsertCount != facts.TableCount ||
		facts.TableSelectGrantOptionCount != 0 ||
		facts.TableInsertGrantOptionCount != 0 ||
		facts.TableUpdateCount != 0 ||
		facts.TableDeleteCount != 0 ||
		facts.TableTruncateCount != 0 ||
		facts.TableReferencesCount != 0 ||
		facts.TableTriggerCount != 0 ||
		facts.TableMaintainCount != 0 ||
		facts.TableColumnUpdateCount != 0 ||
		facts.TableColumnReferencesCount != 0 {
		return sorPostgreSQLDatabaseResourceOwnedDrift
	}

	if facts.SequenceUsageCount != facts.SequenceCount ||
		facts.SequenceSelectCount != facts.SequenceCount ||
		facts.SequenceUsageGrantOptionCount != 0 ||
		facts.SequenceSelectGrantOptionCount != 0 ||
		facts.SequenceUpdateCount != 0 {
		return sorPostgreSQLDatabaseResourceOwnedDrift
	}

	if !facts.DefaultTableSelect ||
		!facts.DefaultTableInsert ||
		facts.DefaultTableSelectGrantOption ||
		facts.DefaultTableInsertGrantOption ||
		facts.DefaultTableUpdate ||
		facts.DefaultTableDelete ||
		facts.DefaultTableTruncate ||
		facts.DefaultTableReferences ||
		facts.DefaultTableTrigger ||
		facts.DefaultTableMaintain {
		return sorPostgreSQLDatabaseResourceOwnedDrift
	}

	if !facts.DefaultSequenceUsage ||
		!facts.DefaultSequenceSelect ||
		facts.DefaultSequenceUsageGrantOption ||
		facts.DefaultSequenceSelectGrantOption ||
		facts.DefaultSequenceUpdate {
		return sorPostgreSQLDatabaseResourceOwnedDrift
	}

	return sorPostgreSQLDatabaseResourceOwnedMatch
}

func classifySORPostgreSQLDatabaseCredential(
	facts sorPostgreSQLDatabaseCredentialFacts,
) sorPostgreSQLDatabaseResourceState {
	if !facts.Observed {
		return sorPostgreSQLDatabaseResourceUnknown
	}

	if !facts.RoleExists {
		if facts.PasswordPresent ||
			facts.SCRAMSHA256 ||
			facts.MatchesPassfile {
			return sorPostgreSQLDatabaseResourceOwnedDrift
		}

		return sorPostgreSQLDatabaseResourceAbsent
	}

	if !facts.PasswordPresent ||
		!facts.SCRAMSHA256 ||
		!facts.MatchesPassfile {
		return sorPostgreSQLDatabaseResourceOwnedDrift
	}

	return sorPostgreSQLDatabaseResourceOwnedMatch
}

func classifySORPostgreSQLDatabasePassfile(
	facts sorPostgreSQLDatabasePassfileFacts,
) sorPostgreSQLDatabaseResourceState {
	if !facts.Observed {
		return sorPostgreSQLDatabaseResourceUnknown
	}

	if !facts.Exists {
		return sorPostgreSQLDatabaseResourceAbsent
	}

	if !facts.Regular ||
		facts.LinkCount != 1 ||
		facts.UID != sorPostgreSQLDatabasePassfileUID ||
		facts.GID != sorPostgreSQLDatabasePassfileGID ||
		facts.Mode != sorPostgreSQLDatabasePassfileMode ||
		!facts.PrefixMatches ||
		!facts.SecretValid {
		return sorPostgreSQLDatabaseResourceOwnedDrift
	}

	return sorPostgreSQLDatabaseResourceOwnedMatch
}
