// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"encoding/csv"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
)

const sorPostgreSQLDatabasePSQLMaximumOutput = 64 * 1024

type sorPostgreSQLDatabaseQueryExecutor struct {
	execute func(
		string,
		...string,
	) ([]byte, error)
}

func (
	executor sorPostgreSQLDatabaseQueryExecutor,
) Query(
	database string,
	query string,
	expectedFields int,
) ([]string, error) {
	if database == "" {
		return nil, fmt.Errorf(
			"PostgreSQL query database is required",
		)
	}

	if strings.TrimSpace(query) == "" {
		return nil, fmt.Errorf(
			"PostgreSQL query is required",
		)
	}

	if expectedFields < 1 {
		return nil, fmt.Errorf(
			"PostgreSQL query expected field count must be positive",
		)
	}

	execute := executor.execute

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

	output, err :=
		execute(
			"/usr/sbin/jexec",
			"-U",
			"postgres",
			"fi-sor-db",
			"/usr/local/bin/psql",
			"-X",
			"-q",
			"-t",
			"--csv",
			"-w",
			"-U",
			"postgres",
			"-h",
			"/tmp",
			"-p",
			"5432",
			"-v",
			"ON_ERROR_STOP=1",
			"-d",
			database,
			"-c",
			query,
		)

	if err != nil {
		// Do not include PostgreSQL output here. Credential observation later
		// queries pg_authid and may receive a SCRAM verifier on stdout.
		return nil, fmt.Errorf(
			"execute FI PostgreSQL catalog query: %w",
			err,
		)
	}

	return parseSORPostgreSQLDatabasePSQLOutput(
		output,
		expectedFields,
	)
}

func parseSORPostgreSQLDatabasePSQLBool(
	value string,
) (bool, error) {
	switch value {
	case "t":
		return true, nil

	case "f":
		return false, nil

	default:
		return false, fmt.Errorf(
			"invalid PostgreSQL boolean %q",
			value,
		)
	}
}

func parseSORPostgreSQLDatabasePSQLInt(
	value string,
) (int, error) {
	parsed, err :=
		strconv.Atoi(
			value,
		)
	if err != nil {
		return 0, fmt.Errorf(
			"invalid PostgreSQL integer %q: %w",
			value,
			err,
		)
	}

	if strconv.Itoa(parsed) != value {
		return 0, fmt.Errorf(
			"non-canonical PostgreSQL integer %q",
			value,
		)
	}

	return parsed, nil
}

func parseSORPostgreSQLDatabasePSQLOutput(
	output []byte,
	expectedFields int,
) ([]string, error) {
	if expectedFields < 1 {
		return nil, fmt.Errorf(
			"PostgreSQL query expected field count must be positive",
		)
	}

	if len(output) >
		sorPostgreSQLDatabasePSQLMaximumOutput {
		return nil, fmt.Errorf(
			"PostgreSQL query output exceeds accepted bound",
		)
	}

	reader :=
		csv.NewReader(
			strings.NewReader(
				string(output),
			),
		)

	reader.FieldsPerRecord =
		expectedFields

	record, err :=
		reader.Read()
	if err != nil {
		if err == io.EOF {
			return nil, fmt.Errorf(
				"PostgreSQL query returned no rows",
			)
		}

		return nil, fmt.Errorf(
			"parse PostgreSQL query result: %w",
			err,
		)
	}

	_, err =
		reader.Read()

	if err == nil {
		return nil, fmt.Errorf(
			"PostgreSQL query returned more than one row",
		)
	}

	if err != io.EOF {
		return nil, fmt.Errorf(
			"parse trailing PostgreSQL query result: %w",
			err,
		)
	}

	return record, nil
}
