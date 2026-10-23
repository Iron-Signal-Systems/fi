// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestBootstrapSORPostgreSQLDatabaseWithExactOrder(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	assets :=
		sorPostgreSQLDatabaseMigrationAssets()

	secret :=
		"0123456789abcdef0123456789abcdef" +
			"0123456789abcdef0123456789abcdef"

	verifier, err :=
		generateSORPostgreSQLDatabaseSCRAMVerifier(
			secret,
			bytes.NewReader(
				bytes.Repeat(
					[]byte{0x5a},
					sorPostgreSQLDatabaseSCRAMSaltBytes,
				),
			),
		)
	if err != nil {
		t.Fatalf(
			"generate verifier: %v",
			err,
		)
	}

	calls :=
		make(
			[]string,
			0,
			12,
		)

	migrationIndex := 0

	err =
		bootstrapSORPostgreSQLDatabaseWith(
			policy,
			assets,
			func() (
				string,
				error,
			) {
				calls =
					append(
						calls,
						"generate-secret",
					)

				return secret, nil
			},
			func(
				observedSecret string,
			) (
				string,
				error,
			) {
				calls =
					append(
						calls,
						"generate-verifier",
					)

				if observedSecret != secret {
					t.Fatal(
						"verifier generator received wrong secret",
					)
				}

				return verifier, nil
			},
			func(
				database string,
				sql []byte,
			) error {
				text :=
					string(sql)

				if strings.Contains(
					text,
					secret,
				) {
					t.Fatal(
						"plaintext credential secret entered bootstrap SQL",
					)
				}

				phase := ""

				switch {
				case strings.Contains(
					text,
					"CREATE ROLE",
				):
					phase = "roles"

				case strings.Contains(
					text,
					"CREATE DATABASE",
				):
					phase = "database"

				case strings.Contains(
					text,
					"REVOKE ALL ON DATABASE",
				):
					phase = "database-hardening"

				case strings.Contains(
					text,
					"REVOKE CREATE ON SCHEMA public",
				):
					phase = "local-hardening"

				case strings.Contains(
					text,
					"COMMENT ON SCHEMA",
				):
					phase = "schema-authority"

				default:
					t.Fatalf(
						"unrecognized bootstrap SQL:\n%s",
						text,
					)
				}

				calls =
					append(
						calls,
						"execute:"+
							database+
							":"+
							phase,
					)

				return nil
			},
			func(
				database string,
				role string,
				sql []byte,
			) error {
				if migrationIndex >=
					len(assets) {
					t.Fatal(
						"too many migration executions",
					)
				}

				if database !=
					policy.DatabaseName {
					t.Fatalf(
						"migration database = %q",
						database,
					)
				}

				if role !=
					policy.OwnerRole.Name {
					t.Fatalf(
						"migration role = %q",
						role,
					)
				}

				if string(sql) !=
					assets[migrationIndex].SQL {
					t.Fatalf(
						"migration %d content changed",
						migrationIndex,
					)
				}

				if strings.Contains(
					string(sql),
					secret,
				) {
					t.Fatal(
						"plaintext credential secret entered migration SQL",
					)
				}

				calls =
					append(
						calls,
						"migration:"+
							assets[migrationIndex].Name,
					)

				migrationIndex++

				return nil
			},
			func(
				observedPolicy sorPostgreSQLDatabasePolicy,
				observedSecret string,
			) error {
				if observedPolicy.PassfilePath !=
					policy.PassfilePath {
					t.Fatal(
						"passfile publication policy changed",
					)
				}

				if observedSecret !=
					secret {
					t.Fatal(
						"passfile publisher received wrong secret",
					)
				}

				calls =
					append(
						calls,
						"publish-passfile",
					)

				return nil
			},
		)
	if err != nil {
		t.Fatalf(
			"bootstrap database: %v",
			err,
		)
	}

	expected :=
		[]string{
			"generate-secret",
			"generate-verifier",
			"execute:postgres:roles",
			"execute:postgres:database",
			"execute:postgres:database-hardening",
			"execute:fi:local-hardening",
			"migration:0001_relational.sql",
			"migration:0002_source_families.sql",
			"migration:0003_usn_relational_identity.sql",
			"migration:0004_security_field_name_index.sql",
			"migration:0005_usn_capture_binding.sql",
			"execute:fi:schema-authority",
			"publish-passfile",
		}

	if !reflect.DeepEqual(
		calls,
		expected,
	) {
		t.Fatalf(
			"bootstrap calls = %#v, want %#v",
			calls,
			expected,
		)
	}
}

func TestBootstrapSORPostgreSQLDatabaseWithMigrationPreflightBeforeDependencies(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	assets :=
		sorPostgreSQLDatabaseMigrationAssets()

	assets[1].Name =
		"unexpected.sql"

	calls := 0

	err :=
		bootstrapSORPostgreSQLDatabaseWith(
			policy,
			assets,
			func() (
				string,
				error,
			) {
				calls++

				return "", nil
			},
			func(
				string,
			) (
				string,
				error,
			) {
				calls++

				return "", nil
			},
			func(
				string,
				[]byte,
			) error {
				calls++

				return nil
			},
			func(
				string,
				string,
				[]byte,
			) error {
				calls++

				return nil
			},
			func(
				sorPostgreSQLDatabasePolicy,
				string,
			) error {
				calls++

				return nil
			},
		)

	if err == nil {
		t.Fatal(
			"bootstrap accepted invalid migration set",
		)
	}

	if calls != 0 {
		t.Fatalf(
			"dependency calls after migration preflight failure = %d, want 0",
			calls,
		)
	}
}

func TestBootstrapSORPostgreSQLDatabaseWithPassfilePreflightBeforeMutation(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	policy.PassfilePrefix = ""

	assets :=
		sorPostgreSQLDatabaseMigrationAssets()

	secret :=
		"0123456789abcdef0123456789abcdef" +
			"0123456789abcdef0123456789abcdef"

	verifier, err :=
		generateSORPostgreSQLDatabaseSCRAMVerifier(
			secret,
			bytes.NewReader(
				bytes.Repeat(
					[]byte{0x42},
					sorPostgreSQLDatabaseSCRAMSaltBytes,
				),
			),
		)
	if err != nil {
		t.Fatalf(
			"generate verifier: %v",
			err,
		)
	}

	executeCalls := 0
	executeAsRoleCalls := 0
	publishCalls := 0

	err =
		bootstrapSORPostgreSQLDatabaseWith(
			policy,
			assets,
			func() (
				string,
				error,
			) {
				return secret, nil
			},
			func(
				string,
			) (
				string,
				error,
			) {
				return verifier, nil
			},
			func(
				string,
				[]byte,
			) error {
				executeCalls++

				return nil
			},
			func(
				string,
				string,
				[]byte,
			) error {
				executeAsRoleCalls++

				return nil
			},
			func(
				sorPostgreSQLDatabasePolicy,
				string,
			) error {
				publishCalls++

				return nil
			},
		)

	if err == nil {
		t.Fatal(
			"bootstrap accepted invalid passfile authority",
		)
	}

	if executeCalls != 0 ||
		executeAsRoleCalls != 0 ||
		publishCalls != 0 {
		t.Fatalf(
			"mutation occurred before passfile preflight: execute=%d role=%d publish=%d",
			executeCalls,
			executeAsRoleCalls,
			publishCalls,
		)
	}
}

func TestBootstrapSORPostgreSQLDatabaseWithStopsOnMigrationFailure(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	assets :=
		sorPostgreSQLDatabaseMigrationAssets()

	secret :=
		"0123456789abcdef0123456789abcdef" +
			"0123456789abcdef0123456789abcdef"

	verifier, err :=
		generateSORPostgreSQLDatabaseSCRAMVerifier(
			secret,
			bytes.NewReader(
				bytes.Repeat(
					[]byte{0x24},
					sorPostgreSQLDatabaseSCRAMSaltBytes,
				),
			),
		)
	if err != nil {
		t.Fatalf(
			"generate verifier: %v",
			err,
		)
	}

	sentinel :=
		errors.New(
			"synthetic migration execution failure",
		)

	executeCalls := 0
	migrationCalls := 0
	publishCalls := 0

	err =
		bootstrapSORPostgreSQLDatabaseWith(
			policy,
			assets,
			func() (
				string,
				error,
			) {
				return secret, nil
			},
			func(
				string,
			) (
				string,
				error,
			) {
				return verifier, nil
			},
			func(
				string,
				[]byte,
			) error {
				executeCalls++

				return nil
			},
			func(
				string,
				string,
				[]byte,
			) error {
				migrationCalls++

				if migrationCalls == 2 {
					return sentinel
				}

				return nil
			},
			func(
				sorPostgreSQLDatabasePolicy,
				string,
			) error {
				publishCalls++

				return nil
			},
		)

	if err == nil {
		t.Fatal(
			"bootstrap accepted migration execution failure",
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

	if executeCalls != 4 {
		t.Fatalf(
			"plain SQL executions = %d, want 4",
			executeCalls,
		)
	}

	if migrationCalls != 2 {
		t.Fatalf(
			"migration executions = %d, want 2",
			migrationCalls,
		)
	}

	if publishCalls != 0 {
		t.Fatalf(
			"passfile published after migration failure: %d",
			publishCalls,
		)
	}
}

func TestBootstrapSORPostgreSQLDatabaseWithStopsOnDatabaseCreationFailure(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	assets :=
		sorPostgreSQLDatabaseMigrationAssets()

	secret :=
		"0123456789abcdef0123456789abcdef" +
			"0123456789abcdef0123456789abcdef"

	verifier, err :=
		generateSORPostgreSQLDatabaseSCRAMVerifier(
			secret,
			bytes.NewReader(
				bytes.Repeat(
					[]byte{0x11},
					sorPostgreSQLDatabaseSCRAMSaltBytes,
				),
			),
		)
	if err != nil {
		t.Fatalf(
			"generate verifier: %v",
			err,
		)
	}

	sentinel :=
		errors.New(
			"synthetic database creation failure",
		)

	executeCalls := 0
	migrationCalls := 0
	publishCalls := 0

	err =
		bootstrapSORPostgreSQLDatabaseWith(
			policy,
			assets,
			func() (
				string,
				error,
			) {
				return secret, nil
			},
			func(
				string,
			) (
				string,
				error,
			) {
				return verifier, nil
			},
			func(
				string,
				[]byte,
			) error {
				executeCalls++

				if executeCalls == 2 {
					return sentinel
				}

				return nil
			},
			func(
				string,
				string,
				[]byte,
			) error {
				migrationCalls++

				return nil
			},
			func(
				sorPostgreSQLDatabasePolicy,
				string,
			) error {
				publishCalls++

				return nil
			},
		)

	if err == nil {
		t.Fatal(
			"bootstrap accepted database creation failure",
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
			"plain SQL executions = %d, want 2",
			executeCalls,
		)
	}

	if migrationCalls != 0 {
		t.Fatalf(
			"migration executed after database creation failure: %d",
			migrationCalls,
		)
	}

	if publishCalls != 0 {
		t.Fatalf(
			"passfile published after database creation failure: %d",
			publishCalls,
		)
	}
}

func TestPrepareSORPostgreSQLDatabaseBootstrapWithCopiesAuthority(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	assets :=
		sorPostgreSQLDatabaseMigrationAssets()

	secret :=
		"0123456789abcdef0123456789abcdef" +
			"0123456789abcdef0123456789abcdef"

	verifier, err :=
		generateSORPostgreSQLDatabaseSCRAMVerifier(
			secret,
			bytes.NewReader(
				bytes.Repeat(
					[]byte{0x33},
					sorPostgreSQLDatabaseSCRAMSaltBytes,
				),
			),
		)
	if err != nil {
		t.Fatalf(
			"generate verifier: %v",
			err,
		)
	}

	plan, err :=
		prepareSORPostgreSQLDatabaseBootstrapWith(
			policy,
			assets,
			func() (
				string,
				error,
			) {
				return secret, nil
			},
			func(
				observedSecret string,
			) (
				string,
				error,
			) {
				if observedSecret != secret {
					t.Fatal(
						"verifier generator received wrong secret",
					)
				}

				return verifier, nil
			},
		)
	if err != nil {
		t.Fatalf(
			"prepare bootstrap: %v",
			err,
		)
	}

	expectedMigrationName :=
		plan.Assets[0].Name

	expectedPolicyMigrationName :=
		plan.Policy.Migrations[0].Name

	assets[0].Name =
		"caller-mutated-asset.sql"

	assets[0].SQL =
		"caller mutated SQL"

	policy.Migrations[0].Name =
		"caller-mutated-policy.sql"

	if plan.Assets[0].Name !=
		expectedMigrationName {
		t.Fatal(
			"prepared migration asset changed with caller slice",
		)
	}

	if plan.Policy.Migrations[0].Name !=
		expectedPolicyMigrationName {
		t.Fatal(
			"prepared migration policy changed with caller slice",
		)
	}

	migrationCalls := 0

	if err :=
		applySORPostgreSQLDatabaseBootstrapPlan(
			plan,
			func(
				string,
				[]byte,
			) error {
				return nil
			},
			func(
				string,
				string,
				[]byte,
			) error {
				migrationCalls++

				return nil
			},
			func(
				sorPostgreSQLDatabasePolicy,
				string,
			) error {
				return nil
			},
		); err != nil {
		t.Fatalf(
			"apply prepared bootstrap: %v",
			err,
		)
	}

	if migrationCalls !=
		len(plan.Assets) {
		t.Fatalf(
			"migration calls = %d, want %d",
			migrationCalls,
			len(plan.Assets),
		)
	}
}

func TestPrepareSORPostgreSQLDatabaseBootstrapWithRejectsMigrationBeforeCredentialGeneration(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	assets :=
		sorPostgreSQLDatabaseMigrationAssets()

	assets[1].Name =
		"unexpected.sql"

	generateSecretCalls := 0
	generateVerifierCalls := 0

	_, err :=
		prepareSORPostgreSQLDatabaseBootstrapWith(
			policy,
			assets,
			func() (
				string,
				error,
			) {
				generateSecretCalls++

				return "", nil
			},
			func(
				string,
			) (
				string,
				error,
			) {
				generateVerifierCalls++

				return "", nil
			},
		)

	if err == nil {
		t.Fatal(
			"prepare accepted invalid migration set",
		)
	}

	if generateSecretCalls != 0 ||
		generateVerifierCalls != 0 {
		t.Fatalf(
			"credential generation occurred before static migration validation: secret=%d verifier=%d",
			generateSecretCalls,
			generateVerifierCalls,
		)
	}
}

func TestApplySORPostgreSQLDatabaseBootstrapPlanRejectsIncompletePlanWithoutMutation(
	t *testing.T,
) {
	executeCalls := 0
	executeAsRoleCalls := 0
	publishCalls := 0

	err :=
		applySORPostgreSQLDatabaseBootstrapPlan(
			sorPostgreSQLDatabaseBootstrapPlan{},
			func(
				string,
				[]byte,
			) error {
				executeCalls++

				return nil
			},
			func(
				string,
				string,
				[]byte,
			) error {
				executeAsRoleCalls++

				return nil
			},
			func(
				sorPostgreSQLDatabasePolicy,
				string,
			) error {
				publishCalls++

				return nil
			},
		)

	if err == nil {
		t.Fatal(
			"apply accepted empty bootstrap plan",
		)
	}

	if executeCalls != 0 ||
		executeAsRoleCalls != 0 ||
		publishCalls != 0 {
		t.Fatalf(
			"mutation occurred from invalid plan: execute=%d role=%d publish=%d",
			executeCalls,
			executeAsRoleCalls,
			publishCalls,
		)
	}
}
