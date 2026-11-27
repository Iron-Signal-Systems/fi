// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestApplySORPostgreSQLDatabaseMigrationsExactOrder(
	t *testing.T,
) {
	assets :=
		testSORPostgreSQLDatabaseMigrationApplicatorAssets()

	policy :=
		testSORPostgreSQLDatabaseMigrationApplicatorPolicy(
			assets,
		)

	var databases []string
	var inputs []string

	err :=
		applySORPostgreSQLDatabaseMigrations(
			policy,
			assets,
			func(
				database string,
				_ string,
				sql []byte,
			) error {
				databases =
					append(
						databases,
						database,
					)

				inputs =
					append(
						inputs,
						string(sql),
					)

				return nil
			},
		)
	if err != nil {
		t.Fatalf(
			"apply migrations: %v",
			err,
		)
	}

	expectedDatabases :=
		[]string{
			"fi",
			"fi",
			"fi",
		}

	if !reflect.DeepEqual(
		databases,
		expectedDatabases,
	) {
		t.Fatalf(
			"databases = %#v, want %#v",
			databases,
			expectedDatabases,
		)
	}

	expectedInputs :=
		[]string{
			assets[0].SQL,
			assets[1].SQL,
			assets[2].SQL,
		}

	if !reflect.DeepEqual(
		inputs,
		expectedInputs,
	) {
		t.Fatalf(
			"migration execution order/content = %#v, want %#v",
			inputs,
			expectedInputs,
		)
	}
}

func TestApplySORPostgreSQLDatabaseMigrationsRejectsAssetCount(
	t *testing.T,
) {
	assets :=
		testSORPostgreSQLDatabaseMigrationApplicatorAssets()

	policy :=
		testSORPostgreSQLDatabaseMigrationApplicatorPolicy(
			assets,
		)

	executeCalls := 0

	err :=
		applySORPostgreSQLDatabaseMigrations(
			policy,
			assets[:2],
			func(
				string,
				string,
				[]byte,
			) error {
				executeCalls++

				return nil
			},
		)

	if err == nil {
		t.Fatal(
			"migration applicator accepted missing asset",
		)
	}

	if executeCalls != 0 {
		t.Fatalf(
			"executor called after asset-count failure: %d",
			executeCalls,
		)
	}
}

func TestApplySORPostgreSQLDatabaseMigrationsRejectsNameMismatch(
	t *testing.T,
) {
	assets :=
		testSORPostgreSQLDatabaseMigrationApplicatorAssets()

	policy :=
		testSORPostgreSQLDatabaseMigrationApplicatorPolicy(
			assets,
		)

	assets[1].Name =
		"unexpected.sql"

	executeCalls := 0

	err :=
		applySORPostgreSQLDatabaseMigrations(
			policy,
			assets,
			func(
				string,
				string,
				[]byte,
			) error {
				executeCalls++

				return nil
			},
		)

	if err == nil {
		t.Fatal(
			"migration applicator accepted name mismatch",
		)
	}

	if executeCalls != 0 {
		t.Fatalf(
			"executor calls = %d, want 0",
			executeCalls,
		)
	}

	if !strings.Contains(
		err.Error(),
		"unexpected.sql",
	) {
		t.Fatalf(
			"error = %q",
			err,
		)
	}
}

func TestApplySORPostgreSQLDatabaseMigrationsRejectsDeclaredHashMismatch(
	t *testing.T,
) {
	assets :=
		testSORPostgreSQLDatabaseMigrationApplicatorAssets()

	policy :=
		testSORPostgreSQLDatabaseMigrationApplicatorPolicy(
			assets,
		)

	assets[1].SHA256 =
		strings.Repeat(
			"0",
			64,
		)

	executeCalls := 0

	err :=
		applySORPostgreSQLDatabaseMigrations(
			policy,
			assets,
			func(
				string,
				string,
				[]byte,
			) error {
				executeCalls++

				return nil
			},
		)

	if err == nil {
		t.Fatal(
			"migration applicator accepted declared hash mismatch",
		)
	}

	if executeCalls != 0 {
		t.Fatalf(
			"executor calls = %d, want 0",
			executeCalls,
		)
	}
}

func TestApplySORPostgreSQLDatabaseMigrationsRejectsEmbeddedHashMismatch(
	t *testing.T,
) {
	assets :=
		testSORPostgreSQLDatabaseMigrationApplicatorAssets()

	policy :=
		testSORPostgreSQLDatabaseMigrationApplicatorPolicy(
			assets,
		)

	assets[1].SQL =
		assets[1].SQL +
			"\n-- mutation\n"

	executeCalls := 0

	err :=
		applySORPostgreSQLDatabaseMigrations(
			policy,
			assets,
			func(
				string,
				string,
				[]byte,
			) error {
				executeCalls++

				return nil
			},
		)

	if err == nil {
		t.Fatal(
			"migration applicator accepted embedded SQL drift",
		)
	}

	if executeCalls != 0 {
		t.Fatalf(
			"executor calls = %d, want 0",
			executeCalls,
		)
	}

	if !strings.Contains(
		err.Error(),
		"embedded SHA256",
	) {
		t.Fatalf(
			"error = %q",
			err,
		)
	}
}

func TestApplySORPostgreSQLDatabaseMigrationsRejectsLaterEmptySQL(
	t *testing.T,
) {
	assets :=
		testSORPostgreSQLDatabaseMigrationApplicatorAssets()

	policy :=
		testSORPostgreSQLDatabaseMigrationApplicatorPolicy(
			assets,
		)

	assets[1].SQL = " \t\r\n "

	executeCalls := 0

	err :=
		applySORPostgreSQLDatabaseMigrations(
			policy,
			assets,
			func(
				string,
				string,
				[]byte,
			) error {
				executeCalls++

				return nil
			},
		)

	if err == nil {
		t.Fatal(
			"migration applicator accepted empty later SQL",
		)
	}

	if executeCalls != 0 {
		t.Fatalf(
			"executor calls = %d, want 0",
			executeCalls,
		)
	}

	if !strings.Contains(
		err.Error(),
		"SQL is empty",
	) {
		t.Fatalf(
			"error = %q",
			err,
		)
	}
}

func TestApplySORPostgreSQLDatabaseMigrationsStopsOnExecutionFailure(
	t *testing.T,
) {
	assets :=
		testSORPostgreSQLDatabaseMigrationApplicatorAssets()

	policy :=
		testSORPostgreSQLDatabaseMigrationApplicatorPolicy(
			assets,
		)

	sentinel :=
		errors.New(
			"synthetic migration failure",
		)

	executeCalls := 0

	err :=
		applySORPostgreSQLDatabaseMigrations(
			policy,
			assets,
			func(
				string,
				string,
				[]byte,
			) error {
				executeCalls++

				if executeCalls == 2 {
					return sentinel
				}

				return nil
			},
		)

	if err == nil {
		t.Fatal(
			"migration execution failure was accepted",
		)
	}

	if !errors.Is(
		err,
		sentinel,
	) {
		t.Fatalf(
			"error = %v, want wrapped sentinel",
			err,
		)
	}

	if executeCalls != 2 {
		t.Fatalf(
			"executor calls = %d, want 2",
			executeCalls,
		)
	}

	if !strings.Contains(
		err.Error(),
		assets[1].Name,
	) {
		t.Fatalf(
			"error = %q",
			err,
		)
	}
}

func TestApplySORPostgreSQLDatabaseMigrationsRequiresAuthority(
	t *testing.T,
) {
	assets :=
		testSORPostgreSQLDatabaseMigrationApplicatorAssets()

	policy :=
		testSORPostgreSQLDatabaseMigrationApplicatorPolicy(
			assets,
		)

	err :=
		applySORPostgreSQLDatabaseMigrations(
			policy,
			assets,
			nil,
		)

	if err == nil ||
		!strings.Contains(
			err.Error(),
			"executor is required",
		) {
		t.Fatalf(
			"nil executor error = %v",
			err,
		)
	}

	policy.DatabaseName = ""

	err =
		applySORPostgreSQLDatabaseMigrations(
			policy,
			assets,
			func(
				string,
				string,
				[]byte,
			) error {
				return nil
			},
		)

	if err == nil ||
		!strings.Contains(
			err.Error(),
			"database is required",
		) {
		t.Fatalf(
			"empty database error = %v",
			err,
		)
	}

	policy =
		testSORPostgreSQLDatabaseMigrationApplicatorPolicy(
			assets,
		)

	policy.Migrations = nil

	err =
		applySORPostgreSQLDatabaseMigrations(
			policy,
			assets,
			func(
				string,
				string,
				[]byte,
			) error {
				return nil
			},
		)

	if err == nil ||
		!strings.Contains(
			err.Error(),
			"policy is empty",
		) {
		t.Fatalf(
			"empty policy error = %v",
			err,
		)
	}
}

func TestValidateSORPostgreSQLDatabaseMigrationsExactSet(
	t *testing.T,
) {
	assets :=
		testSORPostgreSQLDatabaseMigrationApplicatorAssets()

	policy :=
		testSORPostgreSQLDatabaseMigrationApplicatorPolicy(
			assets,
		)

	if err :=
		validateSORPostgreSQLDatabaseMigrations(
			policy,
			assets,
		); err != nil {
		t.Fatalf(
			"validate migrations: %v",
			err,
		)
	}
}

func TestValidateSORPostgreSQLDatabaseMigrationsRejectsLaterDrift(
	t *testing.T,
) {
	assets :=
		testSORPostgreSQLDatabaseMigrationApplicatorAssets()

	policy :=
		testSORPostgreSQLDatabaseMigrationApplicatorPolicy(
			assets,
		)

	assets[1].Name =
		"unexpected.sql"

	if err :=
		validateSORPostgreSQLDatabaseMigrations(
			policy,
			assets,
		); err == nil {
		t.Fatal(
			"migration validator accepted later asset drift",
		)
	}
}

func testSORPostgreSQLDatabaseMigrationApplicatorAssets() []sorPostgreSQLDatabaseMigrationAsset {
	values :=
		[]struct {
			name string
			sql  string
		}{
			{
				name: "0001.sql",
				sql:  "BEGIN;\nSELECT 1;\nCOMMIT;\n",
			},
			{
				name: "0002.sql",
				sql:  "BEGIN;\nSELECT 2;\nCOMMIT;\n",
			},
			{
				name: "0003.sql",
				sql:  "BEGIN;\nSELECT 3;\nCOMMIT;\n",
			},
		}

	assets :=
		make(
			[]sorPostgreSQLDatabaseMigrationAsset,
			0,
			len(values),
		)

	for _, value := range values {
		digest :=
			sha256.Sum256(
				[]byte(
					value.sql,
				),
			)

		assets =
			append(
				assets,
				sorPostgreSQLDatabaseMigrationAsset{
					Name: value.name,
					SHA256: hex.EncodeToString(
						digest[:],
					),
					SQL: value.sql,
				},
			)
	}

	return assets
}

func testSORPostgreSQLDatabaseMigrationApplicatorPolicy(
	assets []sorPostgreSQLDatabaseMigrationAsset,
) sorPostgreSQLDatabasePolicy {
	migrations :=
		make(
			[]sorPostgreSQLDatabaseMigrationPolicy,
			0,
			len(assets),
		)

	for _, asset := range assets {
		migrations =
			append(
				migrations,
				sorPostgreSQLDatabaseMigrationPolicy{
					Name:   asset.Name,
					SHA256: asset.SHA256,
				},
			)
	}

	return sorPostgreSQLDatabasePolicy{
		DatabaseName: "fi",
		Migrations:   migrations,
		OwnerRole: sorPostgreSQLDatabaseRolePolicy{
			Name: "fi_owner",
		},
	}
}

func TestApplySORPostgreSQLDatabaseMigrationsUsesOwnerRole(
	t *testing.T,
) {
	assets :=
		testSORPostgreSQLDatabaseMigrationApplicatorAssets()

	policy :=
		testSORPostgreSQLDatabaseMigrationApplicatorPolicy(
			assets,
		)

	var databases []string
	var roles []string

	err :=
		applySORPostgreSQLDatabaseMigrations(
			policy,
			assets,
			func(
				database string,
				role string,
				_ []byte,
			) error {
				databases =
					append(
						databases,
						database,
					)

				roles =
					append(
						roles,
						role,
					)

				return nil
			},
		)
	if err != nil {
		t.Fatalf(
			"apply migrations: %v",
			err,
		)
	}

	expectedDatabases :=
		[]string{
			"fi",
			"fi",
			"fi",
		}

	if !reflect.DeepEqual(
		databases,
		expectedDatabases,
	) {
		t.Fatalf(
			"databases = %#v, want %#v",
			databases,
			expectedDatabases,
		)
	}

	expectedRoles :=
		[]string{
			"fi_owner",
			"fi_owner",
			"fi_owner",
		}

	if !reflect.DeepEqual(
		roles,
		expectedRoles,
	) {
		t.Fatalf(
			"roles = %#v, want %#v",
			roles,
			expectedRoles,
		)
	}
}

func TestApplySORPostgreSQLDatabaseMigrationsRejectsEmptyOwnerRole(
	t *testing.T,
) {
	assets :=
		testSORPostgreSQLDatabaseMigrationApplicatorAssets()

	policy :=
		testSORPostgreSQLDatabaseMigrationApplicatorPolicy(
			assets,
		)

	policy.OwnerRole.Name = ""

	executeCalls := 0

	err :=
		applySORPostgreSQLDatabaseMigrations(
			policy,
			assets,
			func(
				string,
				string,
				[]byte,
			) error {
				executeCalls++

				return nil
			},
		)

	if err == nil {
		t.Fatal(
			"migration applicator accepted empty owner role",
		)
	}

	if !strings.Contains(
		err.Error(),
		"owner role is required",
	) {
		t.Fatalf(
			"error = %q",
			err,
		)
	}

	if executeCalls != 0 {
		t.Fatalf(
			"executor called with empty owner role: %d",
			executeCalls,
		)
	}
}
