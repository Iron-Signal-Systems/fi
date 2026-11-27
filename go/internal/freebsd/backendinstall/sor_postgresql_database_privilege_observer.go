// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import "fmt"

func observeSORPostgreSQLDatabasePrivileges(
	query func(
		string,
		string,
		int,
	) ([]string, error),
	policy sorPostgreSQLDatabasePolicy,
	catalog sorPostgreSQLDatabaseCatalogFacts,
) (sorPostgreSQLDatabasePrivilegeFacts, error) {
	if !catalog.OwnerRole.Exists ||
		!catalog.IngestRole.Exists ||
		!catalog.Database.Exists ||
		!catalog.Schema.Exists {
		return sorPostgreSQLDatabasePrivilegeFacts{
				Applicable: false,
				Observed:   true,
			},
			nil
	}

	explicit, err :=
		observeSORPostgreSQLDatabaseExplicitPrivileges(
			query,
			policy,
		)
	if err != nil {
		return sorPostgreSQLDatabasePrivilegeFacts{},
			fmt.Errorf(
				"observe PostgreSQL explicit privileges: %w",
				err,
			)
	}

	defaults, err :=
		observeSORPostgreSQLDatabaseDefaultPrivileges(
			query,
			policy,
		)
	if err != nil {
		return sorPostgreSQLDatabasePrivilegeFacts{},
			fmt.Errorf(
				"observe PostgreSQL default privileges: %w",
				err,
			)
	}

	facts :=
		mergeSORPostgreSQLDatabasePrivilegeFacts(
			explicit,
			defaults,
		)

	facts.Applicable = true
	facts.Observed = true

	return facts, nil
}

func mergeSORPostgreSQLDatabasePrivilegeFacts(
	explicit sorPostgreSQLDatabasePrivilegeFacts,
	defaults sorPostgreSQLDatabasePrivilegeFacts,
) sorPostgreSQLDatabasePrivilegeFacts {
	return sorPostgreSQLDatabasePrivilegeFacts{
		DatabaseConnect:            explicit.DatabaseConnect,
		DatabaseConnectGrantOption: explicit.DatabaseConnectGrantOption,
		DatabaseCreate:             explicit.DatabaseCreate,
		DatabaseTemporary:          explicit.DatabaseTemporary,
		PublicDatabaseConnect:      explicit.PublicDatabaseConnect,
		PublicDatabaseCreate:       explicit.PublicDatabaseCreate,
		PublicDatabaseTemporary:    explicit.PublicDatabaseTemporary,

		SchemaUsage:               explicit.SchemaUsage,
		SchemaUsageGrantOption:    explicit.SchemaUsageGrantOption,
		SchemaCreate:              explicit.SchemaCreate,
		PublicSchemaUsage:         explicit.PublicSchemaUsage,
		PublicSchemaCreate:        explicit.PublicSchemaCreate,
		PublicDefaultSchemaCreate: explicit.PublicDefaultSchemaCreate,

		UnexpectedExplicitACLGrantCount: explicit.UnexpectedExplicitACLGrantCount,

		TableCount:                  explicit.TableCount,
		TableSelectCount:            explicit.TableSelectCount,
		TableInsertCount:            explicit.TableInsertCount,
		TableSelectGrantOptionCount: explicit.TableSelectGrantOptionCount,
		TableInsertGrantOptionCount: explicit.TableInsertGrantOptionCount,
		TableUpdateCount:            explicit.TableUpdateCount,
		TableDeleteCount:            explicit.TableDeleteCount,
		TableTruncateCount:          explicit.TableTruncateCount,
		TableReferencesCount:        explicit.TableReferencesCount,
		TableTriggerCount:           explicit.TableTriggerCount,
		TableMaintainCount:          explicit.TableMaintainCount,
		TableColumnUpdateCount:      explicit.TableColumnUpdateCount,
		TableColumnReferencesCount:  explicit.TableColumnReferencesCount,

		SequenceCount:                  explicit.SequenceCount,
		SequenceUsageCount:             explicit.SequenceUsageCount,
		SequenceSelectCount:            explicit.SequenceSelectCount,
		SequenceUsageGrantOptionCount:  explicit.SequenceUsageGrantOptionCount,
		SequenceSelectGrantOptionCount: explicit.SequenceSelectGrantOptionCount,
		SequenceUpdateCount:            explicit.SequenceUpdateCount,

		DefaultTableSelect:            defaults.DefaultTableSelect,
		DefaultTableInsert:            defaults.DefaultTableInsert,
		DefaultTableSelectGrantOption: defaults.DefaultTableSelectGrantOption,
		DefaultTableInsertGrantOption: defaults.DefaultTableInsertGrantOption,
		DefaultTableUpdate:            defaults.DefaultTableUpdate,
		DefaultTableDelete:            defaults.DefaultTableDelete,
		DefaultTableTruncate:          defaults.DefaultTableTruncate,
		DefaultTableReferences:        defaults.DefaultTableReferences,
		DefaultTableTrigger:           defaults.DefaultTableTrigger,
		DefaultTableMaintain:          defaults.DefaultTableMaintain,

		DefaultSequenceUsage: defaults.DefaultSequenceUsage,

		DefaultSequenceSelect: defaults.DefaultSequenceSelect,

		DefaultSequenceUsageGrantOption: defaults.DefaultSequenceUsageGrantOption,

		DefaultSequenceSelectGrantOption: defaults.DefaultSequenceSelectGrantOption,

		DefaultSequenceUpdate: defaults.DefaultSequenceUpdate,

		UnexpectedDefaultACLGrantCount: defaults.UnexpectedDefaultACLGrantCount,
	}
}
