// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"errors"
	"fmt"
	"os/exec"
)

type systemSORPostgreSQLDatabaseBootstrapper struct {
	execute func(
		string,
		...string,
	) ([]byte, error)

	executeSQL sorPostgreSQLDatabaseBootstrapExecuteFunc

	executeSQLAsRole sorPostgreSQLDatabaseBootstrapExecuteAsRoleFunc

	publishPassfile sorPostgreSQLDatabaseBootstrapPublishPassfileFunc

	stagePassfile sorPostgreSQLDatabasePassfilePrepareFunc

	verifySubstrate func(
		Config,
	) error
}

func (
	bootstrapper systemSORPostgreSQLDatabaseBootstrapper,
) Apply(
	config Config,
	plan sorPostgreSQLDatabaseBootstrapPlan,
) (
	returnErr error,
) {
	//
	// A malformed prepared plan must never cause even a jail start.
	//
	if err :=
		validateSORPostgreSQLDatabaseBootstrapPlan(
			plan,
		); err != nil {
		return fmt.Errorf(
			"validate prepared FI PostgreSQL database bootstrap: %w",
			err,
		)
	}

	execute :=
		bootstrapper.execute

	if execute == nil {
		execute = func(
			path string,
			args ...string,
		) ([]byte, error) {
			return exec.Command(
				path,
				args...,
			).CombinedOutput()
		}
	}

	if err :=
		requireSORInitializerJailsStopped(
			execute,
		); err != nil {
		return fmt.Errorf(
			"FI PostgreSQL database bootstrap requires stopped jails: %w",
			err,
		)
	}

	verifySubstrate :=
		bootstrapper.verifySubstrate

	if verifySubstrate == nil {
		verifySubstrate =
			verifySORPostgreSQLInitializationSubstrate
	}

	if err :=
		verifySubstrate(
			config,
		); err != nil {
		return fmt.Errorf(
			"FI PostgreSQL database bootstrap substrate failed: %w",
			err,
		)
	}

	if err :=
		requireSORInitializerPFRuntimeReady(
			execute,
		); err != nil {
		return fmt.Errorf(
			"FI PF runtime is not ready for PostgreSQL database bootstrap: %w",
			err,
		)
	}

	stagePassfile :=
		bootstrapper.stagePassfile

	if stagePassfile == nil {
		stagePassfile =
			stageSORPostgreSQLDatabasePassfile
	}

	stagedPassfile, err :=
		stagePassfile(
			plan.Policy,
			plan.Secret,
		)
	if err != nil {
		return fmt.Errorf(
			"stage FI PostgreSQL ingest passfile before database bootstrap: %w",
			err,
		)
	}

	if err :=
		validateSORPostgreSQLDatabaseStagedPassfile(
			plan.Policy,
			plan.Secret,
			stagedPassfile,
		); err != nil {
		removeSORPostgreSQLPolicyTemp(
			stagedPassfile.Temp,
		)

		return fmt.Errorf(
			"validate staged FI PostgreSQL ingest passfile before database bootstrap: %w",
			err,
		)
	}

	defer removeSORPostgreSQLPolicyTemp(
		stagedPassfile.Temp,
	)

	if err :=
		executeSORInitializerCommand(
			execute,
			"/etc/rc.d/jail",
			"onestart",
			"fi-sor-db",
		); err != nil {
		return fmt.Errorf(
			"start fi-sor-db for PostgreSQL database bootstrap: %w",
			err,
		)
	}

	sorStarted :=
		true

	defer func() {
		if !sorStarted {
			return
		}

		cleanupErr :=
			stopAndVerifySORInitializerJail(
				execute,
			)

		if cleanupErr == nil {
			return
		}

		cleanupErr =
			fmt.Errorf(
				"emergency PostgreSQL database bootstrap cleanup: %w",
				cleanupErr,
			)

		returnErr =
			errors.Join(
				returnErr,
				cleanupErr,
			)
	}()

	if err :=
		executeSORInitializerCommand(
			execute,
			"/usr/sbin/jls",
			"-j",
			"fi-sor-db",
		); err != nil {
		return fmt.Errorf(
			"verify fi-sor-db after database bootstrap start: %w",
			err,
		)
	}

	if err :=
		executeSORInitializerCommand(
			execute,
			"/usr/sbin/jexec",
			"fi-sor-db",
			"/usr/sbin/service",
			"postgresql",
			"onestatus",
		); err != nil {
		return fmt.Errorf(
			"verify PostgreSQL runtime for database bootstrap: %w",
			err,
		)
	}

	executeSQL :=
		bootstrapper.executeSQL

	executeSQLAsRole :=
		bootstrapper.executeSQLAsRole

	if executeSQL == nil ||
		executeSQLAsRole == nil {
		sqlExecutor :=
			sorPostgreSQLDatabaseSQLExecutor{}

		if executeSQL == nil {
			executeSQL =
				sqlExecutor.Execute
		}

		if executeSQLAsRole == nil {
			executeSQLAsRole =
				sqlExecutor.ExecuteAsRole
		}
	}

	publishPassfile :=
		bootstrapper.publishPassfile

	if publishPassfile == nil {
		publishPassfile =
			func(
				policy sorPostgreSQLDatabasePolicy,
				secret string,
			) error {
				return publishStagedSORPostgreSQLDatabasePassfile(
					policy,
					secret,
					stagedPassfile,
				)
			}
	}

	if err :=
		applySORPostgreSQLDatabaseBootstrapPlan(
			plan,
			executeSQL,
			executeSQLAsRole,
			publishPassfile,
		); err != nil {
		return fmt.Errorf(
			"apply FI PostgreSQL database bootstrap plan: %w",
			err,
		)
	}

	if err :=
		stopAndVerifySORInitializerJail(
			execute,
		); err != nil {
		return fmt.Errorf(
			"stop fi-sor-db after PostgreSQL database bootstrap: %w",
			err,
		)
	}

	sorStarted =
		false

	return nil
}
