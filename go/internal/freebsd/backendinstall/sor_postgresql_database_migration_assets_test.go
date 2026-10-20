// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestSORPostgreSQLDatabaseMigrationAssets(
	t *testing.T,
) {
	expected :=
		[]struct {
			name   string
			sha256 string
		}{
			{
				name:   "0001_relational.sql",
				sha256: sorPostgreSQLDatabaseMigration0001SHA256,
			},
			{
				name:   "0002_source_families.sql",
				sha256: sorPostgreSQLDatabaseMigration0002SHA256,
			},
			{
				name:   "0003_usn_relational_identity.sql",
				sha256: sorPostgreSQLDatabaseMigration0003SHA256,
			},
			{
				name:   "0004_security_field_name_index.sql",
				sha256: sorPostgreSQLDatabaseMigration0004SHA256,
			},
		}

	assets :=
		sorPostgreSQLDatabaseMigrationAssets()

	if len(assets) != len(expected) {
		t.Fatalf(
			"migration asset count = %d, want %d",
			len(assets),
			len(expected),
		)
	}

	for index, want := range expected {
		asset :=
			assets[index]

		if asset.Name != want.name {
			t.Fatalf(
				"migration %d name = %q, want %q",
				index,
				asset.Name,
				want.name,
			)
		}

		if asset.SHA256 != want.sha256 {
			t.Fatalf(
				"migration %s declared SHA256 = %q, want %q",
				asset.Name,
				asset.SHA256,
				want.sha256,
			)
		}

		if asset.SQL == "" {
			t.Fatalf(
				"migration %s SQL is empty",
				asset.Name,
			)
		}

		digest :=
			sha256.Sum256(
				[]byte(asset.SQL),
			)

		actual :=
			hex.EncodeToString(
				digest[:],
			)

		if actual != want.sha256 {
			t.Fatalf(
				"migration %s embedded SHA256 = %q, want %q",
				asset.Name,
				actual,
				want.sha256,
			)
		}
	}
}

func TestSORPostgreSQLDatabaseMigrationAssetsReturnIndependentSlice(
	t *testing.T,
) {
	first :=
		sorPostgreSQLDatabaseMigrationAssets()

	second :=
		sorPostgreSQLDatabaseMigrationAssets()

	first[0].Name =
		"mutated"

	if second[0].Name !=
		"0001_relational.sql" {
		t.Fatalf(
			"migration asset slice shares mutable state: %q",
			second[0].Name,
		)
	}
}
