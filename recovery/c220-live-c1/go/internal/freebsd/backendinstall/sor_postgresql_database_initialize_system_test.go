// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

func TestInitializeSORPostgreSQLDatabaseForConfigWithAbsentToOwnedMatch(
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
					[]byte{0x61},
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
			8,
		)

	observeCalls :=
		0

	err =
		initializeSORPostgreSQLDatabaseForConfigWith(
			Config{},
			func(
				Config,
			) error {
				calls =
					append(
						calls,
						"verify-cluster",
					)

				return nil
			},
			func(
				Config,
			) (
				sorPostgreSQLDatabaseObservation,
				sorPostgreSQLDatabaseState,
				error,
			) {
				observeCalls++

				calls =
					append(
						calls,
						"observe",
					)

				if observeCalls == 1 {
					return sorPostgreSQLDatabaseObservation{},
						sorPostgreSQLDatabaseAbsent,
						nil
				}

				return sorPostgreSQLDatabaseObservation{},
					sorPostgreSQLDatabaseOwnedMatch,
					nil
			},
			func(
				Config,
			) (
				sorPostgreSQLDatabasePolicy,
				error,
			) {
				calls =
					append(
						calls,
						"build-policy",
					)

				return policy, nil
			},
			func() []sorPostgreSQLDatabaseMigrationAsset {
				calls =
					append(
						calls,
						"migration-assets",
					)

				return assets
			},
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

				if observedSecret !=
					secret {
					t.Fatal(
						"verifier generator received wrong secret",
					)
				}

				return verifier, nil
			},
			func(
				_ Config,
				plan sorPostgreSQLDatabaseBootstrapPlan,
			) error {
				calls =
					append(
						calls,
						"apply-plan",
					)

				if err :=
					validateSORPostgreSQLDatabaseBootstrapPlan(
						plan,
					); err != nil {
					t.Fatalf(
						"prepared plan invalid: %v",
						err,
					)
				}

				return nil
			},
		)
	if err != nil {
		t.Fatalf(
			"initialize database: %v",
			err,
		)
	}

	expected :=
		[]string{
			"verify-cluster",
			"observe",
			"build-policy",
			"migration-assets",
			"generate-secret",
			"generate-verifier",
			"apply-plan",
			"observe",
		}

	if !reflect.DeepEqual(
		calls,
		expected,
	) {
		t.Fatalf(
			"calls = %#v, want %#v",
			calls,
			expected,
		)
	}
}

func TestInitializeSORPostgreSQLDatabaseForConfigWithOwnedMatchIsNoOp(
	t *testing.T,
) {
	mutationCalls :=
		0

	observeCalls :=
		0

	err :=
		initializeSORPostgreSQLDatabaseForConfigWith(
			Config{},
			func(
				Config,
			) error {
				return nil
			},
			func(
				Config,
			) (
				sorPostgreSQLDatabaseObservation,
				sorPostgreSQLDatabaseState,
				error,
			) {
				observeCalls++

				return sorPostgreSQLDatabaseObservation{},
					sorPostgreSQLDatabaseOwnedMatch,
					nil
			},
			func(
				Config,
			) (
				sorPostgreSQLDatabasePolicy,
				error,
			) {
				mutationCalls++

				return sorPostgreSQLDatabasePolicy{}, nil
			},
			func() []sorPostgreSQLDatabaseMigrationAsset {
				mutationCalls++

				return nil
			},
			func() (
				string,
				error,
			) {
				mutationCalls++

				return "", nil
			},
			func(
				string,
			) (
				string,
				error,
			) {
				mutationCalls++

				return "", nil
			},
			func(
				Config,
				sorPostgreSQLDatabaseBootstrapPlan,
			) error {
				mutationCalls++

				return nil
			},
		)
	if err != nil {
		t.Fatalf(
			"initialize database: %v",
			err,
		)
	}

	if observeCalls != 1 {
		t.Fatalf(
			"observer calls = %d, want 1",
			observeCalls,
		)
	}

	if mutationCalls != 0 {
		t.Fatalf(
			"bootstrap dependencies called from OWNED_MATCH: %d",
			mutationCalls,
		)
	}
}

func TestInitializeSORPostgreSQLDatabaseForConfigWithBlocksDriftBeforePreparation(
	t *testing.T,
) {
	preparationCalls :=
		0

	err :=
		initializeSORPostgreSQLDatabaseForConfigWith(
			Config{},
			func(
				Config,
			) error {
				return nil
			},
			func(
				Config,
			) (
				sorPostgreSQLDatabaseObservation,
				sorPostgreSQLDatabaseState,
				error,
			) {
				return sorPostgreSQLDatabaseObservation{},
					sorPostgreSQLDatabaseOwnedDrift,
					nil
			},
			func(
				Config,
			) (
				sorPostgreSQLDatabasePolicy,
				error,
			) {
				preparationCalls++

				return sorPostgreSQLDatabasePolicy{}, nil
			},
			func() []sorPostgreSQLDatabaseMigrationAsset {
				preparationCalls++

				return nil
			},
			func() (
				string,
				error,
			) {
				preparationCalls++

				return "", nil
			},
			func(
				string,
			) (
				string,
				error,
			) {
				preparationCalls++

				return "", nil
			},
			func(
				Config,
				sorPostgreSQLDatabaseBootstrapPlan,
			) error {
				preparationCalls++

				return nil
			},
		)

	if err == nil {
		t.Fatal(
			"OWNED_DRIFT was accepted",
		)
	}

	if preparationCalls != 0 {
		t.Fatalf(
			"bootstrap preparation ran from OWNED_DRIFT: %d",
			preparationCalls,
		)
	}
}

func TestInitializeSORPostgreSQLDatabaseForConfigWithClusterFailureStopsBeforeObservation(
	t *testing.T,
) {
	sentinel :=
		errors.New(
			"synthetic cluster failure",
		)

	observeCalls :=
		0

	err :=
		initializeSORPostgreSQLDatabaseForConfigWith(
			Config{},
			func(
				Config,
			) error {
				return sentinel
			},
			func(
				Config,
			) (
				sorPostgreSQLDatabaseObservation,
				sorPostgreSQLDatabaseState,
				error,
			) {
				observeCalls++

				return sorPostgreSQLDatabaseObservation{},
					sorPostgreSQLDatabaseAbsent,
					nil
			},
			func(
				Config,
			) (
				sorPostgreSQLDatabasePolicy,
				error,
			) {
				t.Fatal(
					"policy built after cluster failure",
				)

				return sorPostgreSQLDatabasePolicy{}, nil
			},
			func() []sorPostgreSQLDatabaseMigrationAsset {
				t.Fatal(
					"migration assets requested after cluster failure",
				)

				return nil
			},
			func() (
				string,
				error,
			) {
				t.Fatal(
					"credential generated after cluster failure",
				)

				return "", nil
			},
			func(
				string,
			) (
				string,
				error,
			) {
				t.Fatal(
					"verifier generated after cluster failure",
				)

				return "", nil
			},
			func(
				Config,
				sorPostgreSQLDatabaseBootstrapPlan,
			) error {
				t.Fatal(
					"system bootstrap ran after cluster failure",
				)

				return nil
			},
		)

	if err == nil {
		t.Fatal(
			"cluster prerequisite failure was accepted",
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

	if observeCalls != 0 {
		t.Fatalf(
			"observer calls = %d, want 0",
			observeCalls,
		)
	}
}

func TestInitializeSORPostgreSQLDatabaseForConfigWithPreparationFailureStopsBeforeApply(
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

	applyCalls :=
		0

	observeCalls :=
		0

	err :=
		initializeSORPostgreSQLDatabaseForConfigWith(
			Config{},
			func(
				Config,
			) error {
				return nil
			},
			func(
				Config,
			) (
				sorPostgreSQLDatabaseObservation,
				sorPostgreSQLDatabaseState,
				error,
			) {
				observeCalls++

				return sorPostgreSQLDatabaseObservation{},
					sorPostgreSQLDatabaseAbsent,
					nil
			},
			func(
				Config,
			) (
				sorPostgreSQLDatabasePolicy,
				error,
			) {
				return policy, nil
			},
			func() []sorPostgreSQLDatabaseMigrationAsset {
				return assets
			},
			func() (
				string,
				error,
			) {
				t.Fatal(
					"credential generated after migration preflight failure",
				)

				return "", nil
			},
			func(
				string,
			) (
				string,
				error,
			) {
				t.Fatal(
					"verifier generated after migration preflight failure",
				)

				return "", nil
			},
			func(
				Config,
				sorPostgreSQLDatabaseBootstrapPlan,
			) error {
				applyCalls++

				return nil
			},
		)

	if err == nil {
		t.Fatal(
			"invalid migration set was accepted",
		)
	}

	if applyCalls != 0 {
		t.Fatalf(
			"system apply calls = %d, want 0",
			applyCalls,
		)
	}

	if observeCalls != 1 {
		t.Fatalf(
			"observer calls = %d, want 1",
			observeCalls,
		)
	}
}

func TestInitializeSORPostgreSQLDatabaseForConfigWithApplyFailureStopsBeforeFinalObservation(
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
					[]byte{0x37},
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
			"synthetic system bootstrap failure",
		)

	observeCalls :=
		0

	err =
		initializeSORPostgreSQLDatabaseForConfigWith(
			Config{},
			func(
				Config,
			) error {
				return nil
			},
			func(
				Config,
			) (
				sorPostgreSQLDatabaseObservation,
				sorPostgreSQLDatabaseState,
				error,
			) {
				observeCalls++

				return sorPostgreSQLDatabaseObservation{},
					sorPostgreSQLDatabaseAbsent,
					nil
			},
			func(
				Config,
			) (
				sorPostgreSQLDatabasePolicy,
				error,
			) {
				return policy, nil
			},
			func() []sorPostgreSQLDatabaseMigrationAsset {
				return assets
			},
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
				Config,
				sorPostgreSQLDatabaseBootstrapPlan,
			) error {
				return sentinel
			},
		)

	if err == nil {
		t.Fatal(
			"system bootstrap failure was accepted",
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

	if observeCalls != 1 {
		t.Fatalf(
			"final observation ran after bootstrap failure: calls=%d",
			observeCalls,
		)
	}
}
