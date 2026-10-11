// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import "fmt"

type sorPostgreSQLDatabaseObserveFunc func() (
	sorPostgreSQLDatabaseObservation,
	sorPostgreSQLDatabaseState,
	error,
)

func initializeSORPostgreSQLDatabaseWith(
	observe sorPostgreSQLDatabaseObserveFunc,
	initialize func() error,
) error {
	if observe == nil {
		return fmt.Errorf(
			"PostgreSQL database observer is required",
		)
	}

	if initialize == nil {
		return fmt.Errorf(
			"PostgreSQL database initializer is required",
		)
	}

	_,
		initialState,
		err :=
		observe()
	if err != nil {
		return fmt.Errorf(
			"observe initial PostgreSQL database state: %w",
			err,
		)
	}

	switch initialState {
	case sorPostgreSQLDatabaseOwnedMatch:
		return nil

	case sorPostgreSQLDatabaseAbsent:
		// Initialization is authorized only from the exact all-ABSENT
		// semantic state.

	case sorPostgreSQLDatabaseOwnedDrift,
		sorPostgreSQLDatabaseForeignCollision,
		sorPostgreSQLDatabaseUnknown:
		return fmt.Errorf(
			"PostgreSQL database initialization blocked from state %s",
			initialState,
		)

	default:
		return fmt.Errorf(
			"PostgreSQL database initialization blocked from unrecognized state %q",
			initialState,
		)
	}

	if err :=
		initialize(); err != nil {
		return fmt.Errorf(
			"initialize PostgreSQL database: %w",
			err,
		)
	}

	_,
		finalState,
		err :=
		observe()
	if err != nil {
		return fmt.Errorf(
			"observe final PostgreSQL database state: %w",
			err,
		)
	}

	if finalState !=
		sorPostgreSQLDatabaseOwnedMatch {
		return fmt.Errorf(
			"PostgreSQL database initialization did not reach OWNED_MATCH: %s",
			finalState,
		)
	}

	return nil
}
