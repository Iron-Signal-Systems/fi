// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

type sorPostgreSQLDatabaseSQLRunFunc func(
	string,
	[]string,
	[]byte,
) error

type sorPostgreSQLDatabaseSQLExecutor struct {
	run sorPostgreSQLDatabaseSQLRunFunc
}

func buildSORPostgreSQLDatabaseSetRoleSQL(
	role string,
) (string, error) {
	if role == "" {
		return "",
			fmt.Errorf(
				"PostgreSQL SQL role is required",
			)
	}

	if strings.ContainsRune(
		role,
		'\x00',
	) {
		return "",
			fmt.Errorf(
				"PostgreSQL SQL role contains NUL",
			)
	}

	quoted :=
		`"` +
			strings.ReplaceAll(
				role,
				`"`,
				`""`,
			) +
			`"`

	return "SET ROLE " +
			quoted +
			";",
		nil
}

func (
	executor sorPostgreSQLDatabaseSQLExecutor,
) Execute(
	database string,
	sql []byte,
) error {
	return executor.execute(
		database,
		"",
		sql,
	)
}

func (
	executor sorPostgreSQLDatabaseSQLExecutor,
) ExecuteAsRole(
	database string,
	role string,
	sql []byte,
) error {
	setRoleSQL, err :=
		buildSORPostgreSQLDatabaseSetRoleSQL(
			role,
		)
	if err != nil {
		return err
	}

	return executor.execute(
		database,
		setRoleSQL,
		sql,
	)
}

func (
	executor sorPostgreSQLDatabaseSQLExecutor,
) execute(
	database string,
	prefixSQL string,
	sql []byte,
) error {
	if database == "" {
		return fmt.Errorf(
			"PostgreSQL SQL database is required",
		)
	}

	if strings.TrimSpace(
		string(sql),
	) == "" {
		return fmt.Errorf(
			"PostgreSQL SQL input is required",
		)
	}

	run :=
		executor.run

	if run == nil {
		run = func(
			path string,
			args []string,
			input []byte,
		) error {
			command :=
				exec.Command(
					path,
					args...,
				)

			command.Stdin =
				bytes.NewReader(
					input,
				)

			command.Stdout =
				io.Discard

			command.Stderr =
				io.Discard

			return command.Run()
		}
	}

	args :=
		[]string{
			"-U",
			"postgres",
			"fi-sor-db",
			"/usr/local/bin/psql",
			"-X",
			"-q",
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
		}

	if prefixSQL != "" {
		args =
			append(
				args,
				"-c",
				prefixSQL,
			)
	}

	args =
		append(
			args,
			"-f",
			"-",
		)

	if err :=
		run(
			"/usr/sbin/jexec",
			args,
			sql,
		); err != nil {
		return fmt.Errorf(
			"execute FI PostgreSQL SQL: %w",
			err,
		)
	}

	return nil
}
