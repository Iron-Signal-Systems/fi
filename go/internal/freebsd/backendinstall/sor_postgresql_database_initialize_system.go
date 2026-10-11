// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import "fmt"

type sorPostgreSQLDatabaseBuildPolicyFunc func(
	Config,
) (
	sorPostgreSQLDatabasePolicy,
	error,
)

type sorPostgreSQLDatabaseConfigObserveFunc func(
	Config,
) (
	sorPostgreSQLDatabaseObservation,
	sorPostgreSQLDatabaseState,
	error,
)

type sorPostgreSQLDatabaseMigrationAssetsFunc func() []sorPostgreSQLDatabaseMigrationAsset

type sorPostgreSQLDatabaseSystemApplyFunc func(
	Config,
	sorPostgreSQLDatabaseBootstrapPlan,
) error

func InitializeSORPostgreSQLDatabase(
	config Config,
) error {
	observer :=
		systemSORPostgreSQLDatabaseObserver{}

	bootstrapper :=
		systemSORPostgreSQLDatabaseBootstrapper{}

	return initializeSORPostgreSQLDatabaseForConfigWith(
		config,
		VerifySORPostgreSQL,
		observer.Observe,
		buildSORPostgreSQLDatabasePolicy,
		sorPostgreSQLDatabaseMigrationAssets,
		func() (
			string,
			error,
		) {
			return generateSORPostgreSQLDatabaseCredentialSecret(
				nil,
			)
		},
		func(
			secret string,
		) (
			string,
			error,
		) {
			return generateSORPostgreSQLDatabaseSCRAMVerifier(
				secret,
				nil,
			)
		},
		bootstrapper.Apply,
	)
}

func initializeSORPostgreSQLDatabaseForConfigWith(
	config Config,
	verifyCluster func(
		Config,
	) error,
	observe sorPostgreSQLDatabaseConfigObserveFunc,
	buildPolicy sorPostgreSQLDatabaseBuildPolicyFunc,
	migrationAssets sorPostgreSQLDatabaseMigrationAssetsFunc,
	generateSecret sorPostgreSQLDatabaseBootstrapGenerateSecretFunc,
	generateVerifier sorPostgreSQLDatabaseBootstrapGenerateVerifierFunc,
	apply sorPostgreSQLDatabaseSystemApplyFunc,
) error {
	if verifyCluster == nil {
		return fmt.Errorf(
			"PostgreSQL cluster verifier is required for database initialization",
		)
	}

	if observe == nil {
		return fmt.Errorf(
			"PostgreSQL database observer is required for system initialization",
		)
	}

	if buildPolicy == nil {
		return fmt.Errorf(
			"PostgreSQL database policy builder is required for initialization",
		)
	}

	if migrationAssets == nil {
		return fmt.Errorf(
			"PostgreSQL migration asset provider is required for initialization",
		)
	}

	if generateSecret == nil {
		return fmt.Errorf(
			"PostgreSQL credential generator is required for initialization",
		)
	}

	if generateVerifier == nil {
		return fmt.Errorf(
			"PostgreSQL SCRAM verifier generator is required for initialization",
		)
	}

	if apply == nil {
		return fmt.Errorf(
			"PostgreSQL database system bootstrapper is required",
		)
	}

	if err :=
		verifyCluster(
			config,
		); err != nil {
		return fmt.Errorf(
			"PostgreSQL database cluster prerequisite failed: %w",
			err,
		)
	}

	return initializeSORPostgreSQLDatabaseWith(
		func() (
			sorPostgreSQLDatabaseObservation,
			sorPostgreSQLDatabaseState,
			error,
		) {
			return observe(
				config,
			)
		},
		func() error {
			policy, err :=
				buildPolicy(
					config,
				)
			if err != nil {
				return fmt.Errorf(
					"build PostgreSQL database bootstrap policy: %w",
					err,
				)
			}

			assets :=
				migrationAssets()

			plan, err :=
				prepareSORPostgreSQLDatabaseBootstrapWith(
					policy,
					assets,
					generateSecret,
					generateVerifier,
				)
			if err != nil {
				return fmt.Errorf(
					"prepare PostgreSQL database bootstrap: %w",
					err,
				)
			}

			if err :=
				apply(
					config,
					plan,
				); err != nil {
				return fmt.Errorf(
					"apply PostgreSQL database system bootstrap: %w",
					err,
				)
			}

			return nil
		},
	)
}
