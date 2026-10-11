// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import "fmt"

const (
	sorPostgreSQLDatabaseMaintenanceDatabase = "postgres"
)

type sorPostgreSQLDatabaseBootstrapExecuteAsRoleFunc func(
	string,
	string,
	[]byte,
) error

type sorPostgreSQLDatabaseBootstrapExecuteFunc func(
	string,
	[]byte,
) error

type sorPostgreSQLDatabaseBootstrapGenerateSecretFunc func() (
	string,
	error,
)

type sorPostgreSQLDatabaseBootstrapGenerateVerifierFunc func(
	string,
) (
	string,
	error,
)

type sorPostgreSQLDatabaseBootstrapPlan struct {
	Assets              []sorPostgreSQLDatabaseMigrationAsset
	ClusterHardeningSQL []byte
	CreateSQL           []byte
	LocalHardeningSQL   []byte
	Policy              sorPostgreSQLDatabasePolicy
	RoleSQL             []byte
	SchemaAuthoritySQL  []byte
	Secret              string
}

type sorPostgreSQLDatabaseBootstrapPublishPassfileFunc func(
	sorPostgreSQLDatabasePolicy,
	string,
) error

func applySORPostgreSQLDatabaseBootstrapPlan(
	plan sorPostgreSQLDatabaseBootstrapPlan,
	execute sorPostgreSQLDatabaseBootstrapExecuteFunc,
	executeAsRole sorPostgreSQLDatabaseBootstrapExecuteAsRoleFunc,
	publishPassfile sorPostgreSQLDatabaseBootstrapPublishPassfileFunc,
) error {
	if execute == nil {
		return fmt.Errorf(
			"FI PostgreSQL bootstrap executor is required",
		)
	}

	if executeAsRole == nil {
		return fmt.Errorf(
			"FI PostgreSQL bootstrap role executor is required",
		)
	}

	if publishPassfile == nil {
		return fmt.Errorf(
			"FI PostgreSQL passfile publisher is required",
		)
	}

	if err :=
		validateSORPostgreSQLDatabaseBootstrapPlan(
			plan,
		); err != nil {
		return err
	}

	if err :=
		execute(
			sorPostgreSQLDatabaseMaintenanceDatabase,
			plan.RoleSQL,
		); err != nil {
		return fmt.Errorf(
			"create FI PostgreSQL roles: %w",
			err,
		)
	}

	if err :=
		execute(
			sorPostgreSQLDatabaseMaintenanceDatabase,
			plan.CreateSQL,
		); err != nil {
		return fmt.Errorf(
			"create FI PostgreSQL database: %w",
			err,
		)
	}

	if err :=
		execute(
			sorPostgreSQLDatabaseMaintenanceDatabase,
			plan.ClusterHardeningSQL,
		); err != nil {
		return fmt.Errorf(
			"harden FI PostgreSQL database authority: %w",
			err,
		)
	}

	if err :=
		execute(
			plan.Policy.DatabaseName,
			plan.LocalHardeningSQL,
		); err != nil {
		return fmt.Errorf(
			"harden FI PostgreSQL local schema authority: %w",
			err,
		)
	}

	if err :=
		applySORPostgreSQLDatabaseMigrations(
			plan.Policy,
			plan.Assets,
			executeAsRole,
		); err != nil {
		return fmt.Errorf(
			"apply FI PostgreSQL relational foundation: %w",
			err,
		)
	}

	if err :=
		execute(
			plan.Policy.DatabaseName,
			plan.SchemaAuthoritySQL,
		); err != nil {
		return fmt.Errorf(
			"publish FI PostgreSQL schema authority: %w",
			err,
		)
	}

	if err :=
		publishPassfile(
			plan.Policy,
			plan.Secret,
		); err != nil {
		return fmt.Errorf(
			"publish FI PostgreSQL ingest passfile: %w",
			err,
		)
	}

	return nil
}

func validateSORPostgreSQLDatabaseBootstrapPlan(
	plan sorPostgreSQLDatabaseBootstrapPlan,
) error {
	if !isSORPostgreSQLDatabaseCredentialSecret(
		plan.Secret,
	) {
		return fmt.Errorf(
			"FI PostgreSQL bootstrap plan credential is invalid",
		)
	}

	if err :=
		validateSORPostgreSQLDatabaseBootstrapPolicy(
			plan.Policy,
		); err != nil {
		return fmt.Errorf(
			"validate FI PostgreSQL bootstrap plan policy: %w",
			err,
		)
	}

	if err :=
		validateSORPostgreSQLDatabaseMigrations(
			plan.Policy,
			plan.Assets,
		); err != nil {
		return fmt.Errorf(
			"validate FI PostgreSQL bootstrap plan migrations: %w",
			err,
		)
	}

	if len(plan.RoleSQL) == 0 ||
		len(plan.CreateSQL) == 0 ||
		len(plan.ClusterHardeningSQL) == 0 ||
		len(plan.LocalHardeningSQL) == 0 ||
		len(plan.SchemaAuthoritySQL) == 0 {
		return fmt.Errorf(
			"FI PostgreSQL bootstrap plan SQL is incomplete",
		)
	}

	if _, err :=
		buildSORPostgreSQLDatabasePassfileContent(
			plan.Policy,
			plan.Secret,
		); err != nil {
		return fmt.Errorf(
			"validate FI PostgreSQL bootstrap plan passfile: %w",
			err,
		)
	}

	return nil
}

func bootstrapSORPostgreSQLDatabaseWith(
	policy sorPostgreSQLDatabasePolicy,
	assets []sorPostgreSQLDatabaseMigrationAsset,
	generateSecret sorPostgreSQLDatabaseBootstrapGenerateSecretFunc,
	generateVerifier sorPostgreSQLDatabaseBootstrapGenerateVerifierFunc,
	execute sorPostgreSQLDatabaseBootstrapExecuteFunc,
	executeAsRole sorPostgreSQLDatabaseBootstrapExecuteAsRoleFunc,
	publishPassfile sorPostgreSQLDatabaseBootstrapPublishPassfileFunc,
) error {
	if generateSecret == nil {
		return fmt.Errorf(
			"FI PostgreSQL credential generator is required",
		)
	}

	if generateVerifier == nil {
		return fmt.Errorf(
			"FI PostgreSQL SCRAM verifier generator is required",
		)
	}

	if execute == nil {
		return fmt.Errorf(
			"FI PostgreSQL bootstrap executor is required",
		)
	}

	if executeAsRole == nil {
		return fmt.Errorf(
			"FI PostgreSQL bootstrap role executor is required",
		)
	}

	if publishPassfile == nil {
		return fmt.Errorf(
			"FI PostgreSQL passfile publisher is required",
		)
	}

	plan, err :=
		prepareSORPostgreSQLDatabaseBootstrapWith(
			policy,
			assets,
			generateSecret,
			generateVerifier,
		)
	if err != nil {
		return err
	}

	return applySORPostgreSQLDatabaseBootstrapPlan(
		plan,
		execute,
		executeAsRole,
		publishPassfile,
	)
}

func cloneSORPostgreSQLDatabaseBootstrapPolicy(
	policy sorPostgreSQLDatabasePolicy,
) sorPostgreSQLDatabasePolicy {
	cloned :=
		policy

	cloned.Migrations =
		append(
			[]sorPostgreSQLDatabaseMigrationPolicy(nil),
			policy.Migrations...,
		)

	return cloned
}

func prepareSORPostgreSQLDatabaseBootstrapWith(
	policy sorPostgreSQLDatabasePolicy,
	assets []sorPostgreSQLDatabaseMigrationAsset,
	generateSecret sorPostgreSQLDatabaseBootstrapGenerateSecretFunc,
	generateVerifier sorPostgreSQLDatabaseBootstrapGenerateVerifierFunc,
) (
	sorPostgreSQLDatabaseBootstrapPlan,
	error,
) {
	if err :=
		validateSORPostgreSQLDatabaseBootstrapPolicy(
			policy,
		); err != nil {
		return sorPostgreSQLDatabaseBootstrapPlan{},
			fmt.Errorf(
				"validate FI PostgreSQL bootstrap policy: %w",
				err,
			)
	}

	if err :=
		validateSORPostgreSQLDatabaseMigrations(
			policy,
			assets,
		); err != nil {
		return sorPostgreSQLDatabaseBootstrapPlan{},
			fmt.Errorf(
				"validate FI PostgreSQL migrations: %w",
				err,
			)
	}

	if generateSecret == nil {
		return sorPostgreSQLDatabaseBootstrapPlan{},
			fmt.Errorf(
				"FI PostgreSQL credential generator is required",
			)
	}

	if generateVerifier == nil {
		return sorPostgreSQLDatabaseBootstrapPlan{},
			fmt.Errorf(
				"FI PostgreSQL SCRAM verifier generator is required",
			)
	}

	secret, err :=
		generateSecret()
	if err != nil {
		return sorPostgreSQLDatabaseBootstrapPlan{},
			fmt.Errorf(
				"generate FI PostgreSQL credential: %w",
				err,
			)
	}

	if !isSORPostgreSQLDatabaseCredentialSecret(
		secret,
	) {
		return sorPostgreSQLDatabaseBootstrapPlan{},
			fmt.Errorf(
				"generated FI PostgreSQL credential does not satisfy policy",
			)
	}

	verifier, err :=
		generateVerifier(
			secret,
		)
	if err != nil {
		return sorPostgreSQLDatabaseBootstrapPlan{},
			fmt.Errorf(
				"generate FI PostgreSQL SCRAM verifier: %w",
				err,
			)
	}

	roleSQL, err :=
		buildSORPostgreSQLDatabaseRoleBootstrapSQL(
			policy,
			secret,
			verifier,
		)
	if err != nil {
		return sorPostgreSQLDatabaseBootstrapPlan{},
			fmt.Errorf(
				"build FI PostgreSQL role bootstrap SQL: %w",
				err,
			)
	}

	createSQL, err :=
		buildSORPostgreSQLDatabaseCreateSQL(
			policy,
		)
	if err != nil {
		return sorPostgreSQLDatabaseBootstrapPlan{},
			fmt.Errorf(
				"build FI PostgreSQL database creation SQL: %w",
				err,
			)
	}

	clusterHardeningSQL, err :=
		buildSORPostgreSQLDatabaseClusterHardeningSQL(
			policy,
		)
	if err != nil {
		return sorPostgreSQLDatabaseBootstrapPlan{},
			fmt.Errorf(
				"build FI PostgreSQL database hardening SQL: %w",
				err,
			)
	}

	localHardeningSQL, err :=
		buildSORPostgreSQLDatabaseLocalHardeningSQL(
			policy,
		)
	if err != nil {
		return sorPostgreSQLDatabaseBootstrapPlan{},
			fmt.Errorf(
				"build FI PostgreSQL local hardening SQL: %w",
				err,
			)
	}

	schemaAuthoritySQL, err :=
		buildSORPostgreSQLDatabaseSchemaAuthoritySQL(
			policy,
		)
	if err != nil {
		return sorPostgreSQLDatabaseBootstrapPlan{},
			fmt.Errorf(
				"build FI PostgreSQL schema authority SQL: %w",
				err,
			)
	}

	if _, err :=
		buildSORPostgreSQLDatabasePassfileContent(
			policy,
			secret,
		); err != nil {
		return sorPostgreSQLDatabaseBootstrapPlan{},
			fmt.Errorf(
				"preflight FI PostgreSQL passfile: %w",
				err,
			)
	}

	clonedPolicy :=
		cloneSORPostgreSQLDatabaseBootstrapPolicy(
			policy,
		)

	clonedAssets :=
		append(
			[]sorPostgreSQLDatabaseMigrationAsset(nil),
			assets...,
		)

	return sorPostgreSQLDatabaseBootstrapPlan{
			Assets: clonedAssets,
			ClusterHardeningSQL: append(
				[]byte(nil),
				clusterHardeningSQL...,
			),
			CreateSQL: append(
				[]byte(nil),
				createSQL...,
			),
			LocalHardeningSQL: append(
				[]byte(nil),
				localHardeningSQL...,
			),
			Policy: clonedPolicy,
			RoleSQL: append(
				[]byte(nil),
				roleSQL...,
			),
			SchemaAuthoritySQL: append(
				[]byte(nil),
				schemaAuthoritySQL...,
			),
			Secret: secret,
		},
		nil
}
