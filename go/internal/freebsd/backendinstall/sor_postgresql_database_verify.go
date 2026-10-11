// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import "fmt"

func VerifySORPostgreSQLDatabase(
	config Config,
) error {
	observer :=
		systemSORPostgreSQLDatabaseObserver{}

	return verifySORPostgreSQLDatabaseWith(
		config,
		VerifySORPostgreSQL,
		observer.Observe,
	)
}

func verifySORPostgreSQLDatabaseWith(
	config Config,
	verifyCluster func(
		Config,
	) error,
	observe func(
		Config,
	) (
		sorPostgreSQLDatabaseObservation,
		sorPostgreSQLDatabaseState,
		error,
	),
) error {
	if err :=
		verifyCluster(
			config,
		); err != nil {
		return fmt.Errorf(
			"PostgreSQL database cluster prerequisite failed: %w",
			err,
		)
	}

	_,
		state,
		err :=
		observe(
			config,
		)
	if err != nil {
		return fmt.Errorf(
			"observe PostgreSQL database state: %w",
			err,
		)
	}

	if state !=
		sorPostgreSQLDatabaseOwnedMatch {
		return fmt.Errorf(
			"PostgreSQL database is not OWNED_MATCH: %s",
			state,
		)
	}

	return nil
}
