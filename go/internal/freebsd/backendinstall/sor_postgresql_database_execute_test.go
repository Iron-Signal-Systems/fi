// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestSORPostgreSQLDatabaseSQLExecutorDoesNotExposeSQLOnFailure(
	t *testing.T,
) {
	sentinel :=
		errors.New(
			"synthetic psql failure",
		)

	const secret = "DO-NOT-EXPOSE-THIS-SQL"

	executor :=
		sorPostgreSQLDatabaseSQLExecutor{
			run: func(
				string,
				[]string,
				[]byte,
			) error {
				return sentinel
			},
		}

	err :=
		executor.Execute(
			"fi",
			[]byte(
				"SELECT '"+
					secret+
					"';",
			),
		)

	if err == nil {
		t.Fatal(
			"SQL executor accepted command failure",
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

	if strings.Contains(
		err.Error(),
		secret,
	) {
		t.Fatal(
			"SQL executor exposed SQL content",
		)
	}
}

func TestSORPostgreSQLDatabaseSQLExecutorExactCommandAndInput(
	t *testing.T,
) {
	var actualPath string
	var actualArgs []string
	var actualInput []byte

	executor :=
		sorPostgreSQLDatabaseSQLExecutor{
			run: func(
				path string,
				args []string,
				input []byte,
			) error {
				actualPath =
					path

				actualArgs =
					append(
						[]string(nil),
						args...,
					)

				actualInput =
					append(
						[]byte(nil),
						input...,
					)

				return nil
			},
		}

	expectedInput :=
		[]byte(
			"BEGIN;\n" +
				"SELECT 'exact bytes';\n" +
				"COMMIT;\n",
		)

	if err :=
		executor.Execute(
			"fi",
			expectedInput,
		); err != nil {
		t.Fatalf(
			"Execute() error = %v",
			err,
		)
	}

	if actualPath !=
		"/usr/sbin/jexec" {
		t.Fatalf(
			"path = %q, want /usr/sbin/jexec",
			actualPath,
		)
	}

	expectedArgs :=
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
			"fi",
			"-f",
			"-",
		}

	if !reflect.DeepEqual(
		actualArgs,
		expectedArgs,
	) {
		t.Fatalf(
			"args = %#v, want %#v",
			actualArgs,
			expectedArgs,
		)
	}

	if !bytes.Equal(
		actualInput,
		expectedInput,
	) {
		t.Fatalf(
			"SQL input changed:\ngot:  %q\nwant: %q",
			actualInput,
			expectedInput,
		)
	}

	for _, argument := range actualArgs {
		if strings.Contains(
			argument,
			"exact bytes",
		) {
			t.Fatalf(
				"SQL content appeared in argv: %q",
				argument,
			)
		}
	}
}

func TestSORPostgreSQLDatabaseSQLExecutorRejectsEmptyDatabase(
	t *testing.T,
) {
	runCalls := 0

	executor :=
		sorPostgreSQLDatabaseSQLExecutor{
			run: func(
				string,
				[]string,
				[]byte,
			) error {
				runCalls++

				return nil
			},
		}

	err :=
		executor.Execute(
			"",
			[]byte(
				"SELECT 1;",
			),
		)

	if err == nil {
		t.Fatal(
			"SQL executor accepted empty database",
		)
	}

	if runCalls != 0 {
		t.Fatalf(
			"runner called for empty database: %d",
			runCalls,
		)
	}
}

func TestSORPostgreSQLDatabaseSQLExecutorRejectsEmptySQL(
	t *testing.T,
) {
	for _, input := range [][]byte{
		nil,
		{},
		[]byte(""),
		[]byte(" \t\r\n "),
	} {
		runCalls := 0

		executor :=
			sorPostgreSQLDatabaseSQLExecutor{
				run: func(
					string,
					[]string,
					[]byte,
				) error {
					runCalls++

					return nil
				},
			}

		err :=
			executor.Execute(
				"fi",
				input,
			)

		if err == nil {
			t.Fatalf(
				"SQL executor accepted empty SQL %q",
				input,
			)
		}

		if runCalls != 0 {
			t.Fatalf(
				"runner called for empty SQL %q: %d",
				input,
				runCalls,
			)
		}
	}
}

func TestSORPostgreSQLDatabaseSQLExecutorExecuteAsRoleExactCommandAndInput(
	t *testing.T,
) {
	var actualPath string
	var actualArgs []string
	var actualInput []byte

	executor :=
		sorPostgreSQLDatabaseSQLExecutor{
			run: func(
				path string,
				args []string,
				input []byte,
			) error {
				actualPath =
					path

				actualArgs =
					append(
						[]string(nil),
						args...,
					)

				actualInput =
					append(
						[]byte(nil),
						input...,
					)

				return nil
			},
		}

	expectedInput :=
		[]byte(
			"BEGIN;\n" +
				"SELECT 'canonical migration bytes';\n" +
				"COMMIT;\n",
		)

	if err :=
		executor.ExecuteAsRole(
			"fi",
			"fi_owner",
			expectedInput,
		); err != nil {
		t.Fatalf(
			"ExecuteAsRole() error = %v",
			err,
		)
	}

	if actualPath !=
		"/usr/sbin/jexec" {
		t.Fatalf(
			"path = %q, want /usr/sbin/jexec",
			actualPath,
		)
	}

	expectedArgs :=
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
			"fi",
			"-c",
			`SET ROLE "fi_owner";`,
			"-f",
			"-",
		}

	if !reflect.DeepEqual(
		actualArgs,
		expectedArgs,
	) {
		t.Fatalf(
			"args = %#v, want %#v",
			actualArgs,
			expectedArgs,
		)
	}

	if !bytes.Equal(
		actualInput,
		expectedInput,
	) {
		t.Fatalf(
			"SQL input changed:\ngot:  %q\nwant: %q",
			actualInput,
			expectedInput,
		)
	}

	for _, argument := range actualArgs {
		if strings.Contains(
			argument,
			"canonical migration bytes",
		) {
			t.Fatalf(
				"migration SQL appeared in argv: %q",
				argument,
			)
		}
	}
}

func TestSORPostgreSQLDatabaseSQLExecutorExecuteAsRoleQuotesIdentifier(
	t *testing.T,
) {
	var actualArgs []string

	executor :=
		sorPostgreSQLDatabaseSQLExecutor{
			run: func(
				string,
				[]string,
				[]byte,
			) error {
				return nil
			},
		}

	executor.run =
		func(
			_ string,
			args []string,
			_ []byte,
		) error {
			actualArgs =
				append(
					[]string(nil),
					args...,
				)

			return nil
		}

	if err :=
		executor.ExecuteAsRole(
			"fi",
			`owner"role`,
			[]byte(
				"SELECT 1;",
			),
		); err != nil {
		t.Fatalf(
			"ExecuteAsRole() error = %v",
			err,
		)
	}

	found :=
		false

	for index, argument := range actualArgs {
		if argument != "-c" {
			continue
		}

		if index+1 >=
			len(actualArgs) {
			t.Fatal(
				"psql -c missing argument",
			)
		}

		if actualArgs[index+1] !=
			`SET ROLE "owner""role";` {
			t.Fatalf(
				"SET ROLE command = %q",
				actualArgs[index+1],
			)
		}

		found = true
	}

	if !found {
		t.Fatal(
			"role-aware executor omitted psql -c",
		)
	}
}

func TestSORPostgreSQLDatabaseSQLExecutorExecuteAsRoleRejectsInvalidRole(
	t *testing.T,
) {
	for _, role := range []string{
		"",
		"fi_owner\x00unexpected",
	} {
		runCalls := 0

		executor :=
			sorPostgreSQLDatabaseSQLExecutor{
				run: func(
					string,
					[]string,
					[]byte,
				) error {
					runCalls++

					return nil
				},
			}

		err :=
			executor.ExecuteAsRole(
				"fi",
				role,
				[]byte(
					"SELECT 1;",
				),
			)

		if err == nil {
			t.Fatalf(
				"ExecuteAsRole() accepted role %q",
				role,
			)
		}

		if runCalls != 0 {
			t.Fatalf(
				"runner called for invalid role %q: %d",
				role,
				runCalls,
			)
		}
	}
}
