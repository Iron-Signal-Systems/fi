// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"errors"
	"fmt"
	"os/exec"
)

type systemSORPostgreSQLDatabaseObserver struct {
	buildPolicy func(
		Config,
	) (
		sorPostgreSQLDatabasePolicy,
		error,
	)

	execute func(
		string,
		...string,
	) ([]byte, error)

	observe func(
		sorPostgreSQLDatabasePolicy,
	) (
		sorPostgreSQLDatabaseObservation,
		sorPostgreSQLDatabaseState,
		error,
	)

	verifySubstrate func(
		Config,
	) error
}

func (
	observer systemSORPostgreSQLDatabaseObserver,
) Observe(
	config Config,
) (
	observation sorPostgreSQLDatabaseObservation,
	state sorPostgreSQLDatabaseState,
	returnErr error,
) {
	state =
		sorPostgreSQLDatabaseUnknown

	buildPolicy :=
		observer.buildPolicy

	if buildPolicy == nil {
		buildPolicy =
			buildSORPostgreSQLDatabasePolicy
	}

	policy, err :=
		buildPolicy(
			config,
		)
	if err != nil {
		return sorPostgreSQLDatabaseObservation{},
			sorPostgreSQLDatabaseUnknown,
			fmt.Errorf(
				"build PostgreSQL database observation policy: %w",
				err,
			)
	}

	execute :=
		observer.execute

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
		return sorPostgreSQLDatabaseObservation{},
			sorPostgreSQLDatabaseUnknown,
			fmt.Errorf(
				"PostgreSQL database observation requires all FI jails stopped: %w",
				err,
			)
	}

	verifySubstrate :=
		observer.verifySubstrate

	if verifySubstrate == nil {
		verifySubstrate =
			verifySORPostgreSQLInitializationSubstrate
	}

	if err :=
		verifySubstrate(
			config,
		); err != nil {
		return sorPostgreSQLDatabaseObservation{},
			sorPostgreSQLDatabaseUnknown,
			fmt.Errorf(
				"PostgreSQL database observation substrate failed: %w",
				err,
			)
	}

	if err :=
		requireSORInitializerPFRuntimeReady(
			execute,
		); err != nil {
		return sorPostgreSQLDatabaseObservation{},
			sorPostgreSQLDatabaseUnknown,
			fmt.Errorf(
				"FI PF runtime is not ready for PostgreSQL database observation: %w",
				err,
			)
	}

	if err :=
		executeSORInitializerCommand(
			execute,
			"/etc/rc.d/jail",
			"onestart",
			"fi-sor-db",
		); err != nil {
		return sorPostgreSQLDatabaseObservation{},
			sorPostgreSQLDatabaseUnknown,
			fmt.Errorf(
				"start fi-sor-db for PostgreSQL database observation: %w",
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

		state =
			sorPostgreSQLDatabaseUnknown

		cleanupErr =
			fmt.Errorf(
				"emergency PostgreSQL database observation cleanup: %w",
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
		return sorPostgreSQLDatabaseObservation{},
			sorPostgreSQLDatabaseUnknown,
			fmt.Errorf(
				"verify fi-sor-db after database observation start: %w",
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
		return sorPostgreSQLDatabaseObservation{},
			sorPostgreSQLDatabaseUnknown,
			fmt.Errorf(
				"verify PostgreSQL runtime for database observation: %w",
				err,
			)
	}

	observe :=
		observer.observe

	if observe == nil {
		semanticObserver :=
			sorPostgreSQLDatabaseObserver{}

		observe =
			semanticObserver.Observe
	}

	observation,
		state,
		err =
		observe(
			policy,
		)

	if err != nil {
		state =
			sorPostgreSQLDatabaseUnknown

		return observation,
			state,
			fmt.Errorf(
				"observe PostgreSQL database semantic state: %w",
				err,
			)
	}

	return observation,
		state,
		nil
}
