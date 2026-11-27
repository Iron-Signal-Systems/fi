// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"fmt"
	"path/filepath"
)

const (
	sorPostgreSQLDatabaseAuthorityMarker = "FI-MANAGED: ironsignal-fi-freebsd-sor-database-v1"

	sorPostgreSQLDatabaseName = "fi"

	sorPostgreSQLDatabaseOwnerRoleName = "fi_owner"

	sorPostgreSQLDatabaseIngestRoleName = "fi_ingest"

	sorPostgreSQLDatabaseSchemaName = "fi"

	sorPostgreSQLDatabaseExpectedRelationalTableCount = 49

	sorPostgreSQLDatabaseMigration0001SHA256 = "f83ffb7754e22eef6230300b38ff6d1cf039791fd08f356c77efa2e30b462ebf"

	sorPostgreSQLDatabaseMigration0002SHA256 = "82050818f1424b7870a1b992b182abeb5497fe52c5a6f84d08fdefc76c496439"

	sorPostgreSQLDatabaseMigration0003SHA256 = "906dccf64eaf13a0a008bc870801beefb2d372f71574d10fe40ae5f1ba5a174c"

	sorPostgreSQLDatabaseMigration0004SHA256 = "9a2a54875828e82eed9dbbb36ddaa0b6886bdc43789f1a220f41bf40cd1460dc"

	sorPostgreSQLDatabaseMigration0005SHA256 = "687f45c9229e7c3cfd9edca51b565e17b8c3f3b9ca3d674a44787b632d438fab"
)

type sorPostgreSQLDatabaseMigrationPolicy struct {
	Name   string
	SHA256 string
}

type sorPostgreSQLDatabaseRolePolicy struct {
	BypassRLS          bool
	CanLogin           bool
	Comment            string
	ConnectionLimit    int
	CreateDB           bool
	CreateRole         bool
	Inherit            bool
	Name               string
	PasswordRequired   bool
	Replication        bool
	Superuser          bool
	ValidUntilInfinity bool
}

type sorPostgreSQLDatabasePolicy struct {
	CoreTables                   []string
	DatabaseComment              string
	DatabaseCollate              string
	DatabaseCType                string
	DatabaseEncoding             string
	DatabaseName                 string
	DatabaseOwner                string
	ExpectedRelationalTableCount int
	IngestRole                   sorPostgreSQLDatabaseRolePolicy
	IngestWorkAddress            string
	Migrations                   []sorPostgreSQLDatabaseMigrationPolicy
	OwnerRole                    sorPostgreSQLDatabaseRolePolicy
	PassfilePath                 string
	PassfilePrefix               string
	SchemaComment                string
	SchemaName                   string
	SchemaOwner                  string
	SORWorkAddress               string
}

func buildSORPostgreSQLDatabasePolicy(
	config Config,
) (sorPostgreSQLDatabasePolicy, error) {
	sorWorkAddress, err :=
		sorPostgreSQLWorkAddress(
			config.Value(
				"FI_SOR_DB_WORK_ADDRESS",
			),
		)
	if err != nil {
		return sorPostgreSQLDatabasePolicy{},
			fmt.Errorf(
				"invalid FI SOR database workload address: %w",
				err,
			)
	}

	ingestWorkAddress, err :=
		sorPostgreSQLWorkAddress(
			config.Value(
				"FI_INGEST_WORK_ADDRESS",
			),
		)
	if err != nil {
		return sorPostgreSQLDatabasePolicy{},
			fmt.Errorf(
				"invalid FI ingest workload address: %w",
				err,
			)
	}

	ingestConfigHost :=
		config.Value(
			"FI_INGEST_CONFIG_HOST",
		)

	if ingestConfigHost == "" {
		return sorPostgreSQLDatabasePolicy{},
			fmt.Errorf(
				"FI ingest configuration host path is required",
			)
	}

	ownerComment :=
		sorPostgreSQLDatabaseAuthorityMarker +
			"\nFI-ROLE: database-owner"

	ingestComment :=
		sorPostgreSQLDatabaseAuthorityMarker +
			"\nFI-ROLE: database-ingest"

	databaseComment :=
		sorPostgreSQLDatabaseAuthorityMarker +
			"\nFI-ROLE: authoritative-database"

	schemaComment :=
		sorPostgreSQLDatabaseAuthorityMarker +
			"\nFI-ROLE: relational-schema" +
			"\nFI-FOUNDATION:" +
			" 0001@" +
			sorPostgreSQLDatabaseMigration0001SHA256 +
			";0002@" +
			sorPostgreSQLDatabaseMigration0002SHA256 +
			";0003@" +
			sorPostgreSQLDatabaseMigration0003SHA256

	return sorPostgreSQLDatabasePolicy{
		CoreTables: []string{
			"recorded_generation",
			"source_batch",
			"source_record",
			"ingest_journal",
			"ntfs_volume",
			"ntfs_object",
			"governed_root",
			"file_observation",
			"usn_read_boundary",
			"usn_object_observation",
			"usn_object_change",
			"windows_security_event",
		},

		DatabaseComment: databaseComment,

		DatabaseCollate: "C.UTF-8",

		DatabaseCType: "C.UTF-8",

		DatabaseEncoding: "UTF8",

		DatabaseName: sorPostgreSQLDatabaseName,

		DatabaseOwner: sorPostgreSQLDatabaseOwnerRoleName,

		ExpectedRelationalTableCount: sorPostgreSQLDatabaseExpectedRelationalTableCount,

		IngestRole: sorPostgreSQLDatabaseRolePolicy{
			BypassRLS:          false,
			CanLogin:           true,
			Comment:            ingestComment,
			ConnectionLimit:    -1,
			CreateDB:           false,
			CreateRole:         false,
			Inherit:            true,
			Name:               sorPostgreSQLDatabaseIngestRoleName,
			PasswordRequired:   true,
			Replication:        false,
			Superuser:          false,
			ValidUntilInfinity: true,
		},

		IngestWorkAddress: ingestWorkAddress,

		Migrations: []sorPostgreSQLDatabaseMigrationPolicy{
			{
				Name:   "0001_relational.sql",
				SHA256: sorPostgreSQLDatabaseMigration0001SHA256,
			},
			{
				Name:   "0002_source_families.sql",
				SHA256: sorPostgreSQLDatabaseMigration0002SHA256,
			},
			{
				Name:   "0003_usn_relational_identity.sql",
				SHA256: sorPostgreSQLDatabaseMigration0003SHA256,
			},
			{
				Name:   "0004_security_field_name_index.sql",
				SHA256: sorPostgreSQLDatabaseMigration0004SHA256,
			},
			{
				Name:   "0005_usn_capture_binding.sql",
				SHA256: sorPostgreSQLDatabaseMigration0005SHA256,
			},
		},

		OwnerRole: sorPostgreSQLDatabaseRolePolicy{
			BypassRLS:          false,
			CanLogin:           false,
			Comment:            ownerComment,
			ConnectionLimit:    -1,
			CreateDB:           false,
			CreateRole:         false,
			Inherit:            true,
			Name:               sorPostgreSQLDatabaseOwnerRoleName,
			PasswordRequired:   false,
			Replication:        false,
			Superuser:          false,
			ValidUntilInfinity: true,
		},

		PassfilePath: filepath.Join(
			ingestConfigHost,
			"postgres.pgpass",
		),

		PassfilePrefix: sorWorkAddress +
			":5432:" +
			sorPostgreSQLDatabaseName +
			":" +
			sorPostgreSQLDatabaseIngestRoleName +
			":",

		SchemaComment: schemaComment,

		SchemaName: sorPostgreSQLDatabaseSchemaName,

		SchemaOwner: sorPostgreSQLDatabaseOwnerRoleName,

		SORWorkAddress: sorWorkAddress,
	}, nil
}
