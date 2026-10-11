// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import "fmt"

type sorPostgreSQLDatabaseObserver struct {
	inspectPassfile func(
		sorPostgreSQLDatabasePolicy,
	) (
		sorPostgreSQLDatabasePassfileFacts,
		string,
		error,
	)

	query func(
		string,
		string,
		int,
	) ([]string, error)
}

func (
	observer sorPostgreSQLDatabaseObserver,
) Observe(
	policy sorPostgreSQLDatabasePolicy,
) (
	sorPostgreSQLDatabaseObservation,
	sorPostgreSQLDatabaseState,
	error,
) {
	query :=
		observer.query

	if query == nil {
		executor :=
			sorPostgreSQLDatabaseQueryExecutor{}

		query =
			executor.Query
	}

	inspectPassfile :=
		observer.inspectPassfile

	if inspectPassfile == nil {
		inspectPassfile =
			inspectSORPostgreSQLDatabasePassfile
	}

	catalogObserver :=
		sorPostgreSQLDatabaseCatalogObserver{
			query: query,
		}

	catalog, err :=
		catalogObserver.Observe(
			policy,
		)
	if err != nil {
		return sorPostgreSQLDatabaseObservation{},
			sorPostgreSQLDatabaseUnknown,
			fmt.Errorf(
				"observe PostgreSQL database catalog: %w",
				err,
			)
	}

	observation :=
		classifySORPostgreSQLDatabaseCatalog(
			policy,
			catalog,
		)

	privileges, err :=
		observeSORPostgreSQLDatabasePrivileges(
			query,
			policy,
			catalog,
		)
	if err != nil {
		return observation,
			sorPostgreSQLDatabaseUnknown,
			fmt.Errorf(
				"observe PostgreSQL database privileges: %w",
				err,
			)
	}

	credential,
		passfile,
		err :=
		observeSORPostgreSQLDatabaseCredentialAndPassfile(
			query,
			inspectPassfile,
			policy,
			catalog,
		)
	if err != nil {
		return observation,
			sorPostgreSQLDatabaseUnknown,
			fmt.Errorf(
				"observe PostgreSQL database credential: %w",
				err,
			)
	}

	observation =
		completeSORPostgreSQLDatabaseObservation(
			observation,
			policy,
			privileges,
			credential,
			passfile,
		)

	return observation,
		classifySORPostgreSQLDatabase(
			observation,
		),
		nil
}
