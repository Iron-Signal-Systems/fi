// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

type sorPostgreSQLDatabaseMigrationAsset struct {
	Name   string
	SHA256 string
	SQL    string
}

func sorPostgreSQLDatabaseMigrationAssets() []sorPostgreSQLDatabaseMigrationAsset {
	return []sorPostgreSQLDatabaseMigrationAsset{
		{
			Name:   "0001_relational.sql",
			SHA256: sorPostgreSQLDatabaseMigration0001SHA256,
			SQL:    sorPostgreSQLDatabaseMigration0001Asset,
		},
		{
			Name:   "0002_source_families.sql",
			SHA256: sorPostgreSQLDatabaseMigration0002SHA256,
			SQL:    sorPostgreSQLDatabaseMigration0002Asset,
		},
		{
			Name:   "0003_usn_relational_identity.sql",
			SHA256: sorPostgreSQLDatabaseMigration0003SHA256,
			SQL:    sorPostgreSQLDatabaseMigration0003Asset,
		},
		{
			Name:   "0004_security_field_name_index.sql",
			SHA256: sorPostgreSQLDatabaseMigration0004SHA256,
			SQL:    sorPostgreSQLDatabaseMigration0004Asset,
		},
	}
}
