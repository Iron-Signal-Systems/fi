//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

// SHA-256 values are pinned to the original canonical SQL migration bytes.
const (
	sorPostgreSQLDatabaseMigration0001SHA256 = "f83ffb7754e22eef6230300b38ff6d1cf039791fd08f356c77efa2e30b462ebf"
	sorPostgreSQLDatabaseMigration0002SHA256 = "82050818f1424b7870a1b992b182abeb5497fe52c5a6f84d08fdefc76c496439"
	sorPostgreSQLDatabaseMigration0003SHA256 = "906dccf64eaf13a0a008bc870801beefb2d372f71574d10fe40ae5f1ba5a174c"
	sorPostgreSQLDatabaseMigration0004SHA256 = "9a2a54875828e82eed9dbbb36ddaa0b6886bdc43789f1a220f41bf40cd1460dc"
	sorPostgreSQLDatabaseMigration0005SHA256 = "687f45c9229e7c3cfd9edca51b565e17b8c3f3b9ca3d674a44787b632d438fab"
	sorPostgreSQLDatabaseMigration0006SHA256 = "0afc7fb2229062bbf91c8d749f1956cdc3f40f2257a314c8605d52f12f3d953e"
)


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
		{
			Name:   "0005_usn_capture_binding.sql",
			SHA256: sorPostgreSQLDatabaseMigration0005SHA256,
			SQL:    sorPostgreSQLDatabaseMigration0005Asset,
		},
		{
			Name:   "0006_usn_scoped_capture.sql",
			SHA256: sorPostgreSQLDatabaseMigration0006SHA256,
			SQL:    sorPostgreSQLDatabaseMigration0006Asset,
		},
	}
}
