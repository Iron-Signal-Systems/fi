// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestSORPostgreSQLDatabasePSQLQueryExactCommand(
	t *testing.T,
) {
	var actualPath string
	var actualArgs []string

	executor :=
		sorPostgreSQLDatabaseQueryExecutor{
			execute: func(
				path string,
				args ...string,
			) ([]byte, error) {
				actualPath = path

				actualArgs =
					append(
						[]string(nil),
						args...,
					)

				return []byte(
						"t,49,\"FI-MANAGED: test\nFI-ROLE: test\"\n",
					),
					nil
			},
		}

	fields, err :=
		executor.Query(
			"postgres",
			"SELECT test",
			3,
		)
	if err != nil {
		t.Fatalf(
			"Query() error = %v",
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
			"postgres",
			"-c",
			"SELECT test",
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

	expectedFields :=
		[]string{
			"t",
			"49",
			"FI-MANAGED: test\nFI-ROLE: test",
		}

	if !reflect.DeepEqual(
		fields,
		expectedFields,
	) {
		t.Fatalf(
			"fields = %#v, want %#v",
			fields,
			expectedFields,
		)
	}
}

func TestSORPostgreSQLDatabasePSQLQueryDoesNotExposeFailedOutput(
	t *testing.T,
) {
	sentinel :=
		errors.New(
			"psql failed",
		)

	executor :=
		sorPostgreSQLDatabaseQueryExecutor{
			execute: func(
				string,
				...string,
			) ([]byte, error) {
				return []byte(
						"SCRAM-SHA-256$4096:do-not-log-this",
					),
					sentinel
			},
		}

	_, err :=
		executor.Query(
			"postgres",
			"SELECT rolpassword FROM pg_authid",
			1,
		)

	if err == nil {
		t.Fatal(
			"Query() accepted command failure",
		)
	}

	if !errors.Is(
		err,
		sentinel,
	) {
		t.Fatalf(
			"Query() error = %v, want wrapped sentinel",
			err,
		)
	}

	if strings.Contains(
		err.Error(),
		"SCRAM-SHA-256",
	) {
		t.Fatal(
			"Query() error exposed PostgreSQL credential output",
		)
	}
}

func TestSORPostgreSQLDatabasePSQLParseEmbeddedNewline(
	t *testing.T,
) {
	fields, err :=
		parseSORPostgreSQLDatabasePSQLOutput(
			[]byte(
				"fi,\"first line\nsecond line\",49\n",
			),
			3,
		)
	if err != nil {
		t.Fatalf(
			"parse output: %v",
			err,
		)
	}

	expected :=
		[]string{
			"fi",
			"first line\nsecond line",
			"49",
		}

	if !reflect.DeepEqual(
		fields,
		expected,
	) {
		t.Fatalf(
			"fields = %#v, want %#v",
			fields,
			expected,
		)
	}
}

func TestSORPostgreSQLDatabasePSQLParseRejectsMultipleRows(
	t *testing.T,
) {
	_, err :=
		parseSORPostgreSQLDatabasePSQLOutput(
			[]byte(
				"one,t\n"+
					"two,f\n",
			),
			2,
		)

	if err == nil {
		t.Fatal(
			"multiple PostgreSQL rows were accepted",
		)
	}
}

func TestSORPostgreSQLDatabasePSQLParseRejectsWrongFieldCount(
	t *testing.T,
) {
	_, err :=
		parseSORPostgreSQLDatabasePSQLOutput(
			[]byte(
				"one,t,extra\n",
			),
			2,
		)

	if err == nil {
		t.Fatal(
			"wrong PostgreSQL field count was accepted",
		)
	}
}

func TestSORPostgreSQLDatabasePSQLParseRejectsNoRows(
	t *testing.T,
) {
	_, err :=
		parseSORPostgreSQLDatabasePSQLOutput(
			nil,
			1,
		)

	if err == nil {
		t.Fatal(
			"empty PostgreSQL result was accepted",
		)
	}
}

func TestSORPostgreSQLDatabasePSQLParseBoundsOutput(
	t *testing.T,
) {
	output :=
		[]byte(
			strings.Repeat(
				"x",
				sorPostgreSQLDatabasePSQLMaximumOutput+1,
			),
		)

	_, err :=
		parseSORPostgreSQLDatabasePSQLOutput(
			output,
			1,
		)

	if err == nil {
		t.Fatal(
			"oversized PostgreSQL result was accepted",
		)
	}
}

func TestSORPostgreSQLDatabasePSQLBoolExact(
	t *testing.T,
) {
	actualTrue, err :=
		parseSORPostgreSQLDatabasePSQLBool(
			"t",
		)
	if err != nil {
		t.Fatalf(
			"parse true: %v",
			err,
		)
	}

	if !actualTrue {
		t.Fatal(
			"PostgreSQL t parsed false",
		)
	}

	actualFalse, err :=
		parseSORPostgreSQLDatabasePSQLBool(
			"f",
		)
	if err != nil {
		t.Fatalf(
			"parse false: %v",
			err,
		)
	}

	if actualFalse {
		t.Fatal(
			"PostgreSQL f parsed true",
		)
	}

	for _, invalid := range []string{
		"",
		"true",
		"false",
		"T",
		"F",
		"1",
		"0",
	} {
		if _, err :=
			parseSORPostgreSQLDatabasePSQLBool(
				invalid,
			); err == nil {
			t.Fatalf(
				"invalid PostgreSQL boolean %q accepted",
				invalid,
			)
		}
	}
}

func TestSORPostgreSQLDatabasePSQLIntExact(
	t *testing.T,
) {
	for _, testCase := range []struct {
		input    string
		expected int
	}{
		{
			input:    "0",
			expected: 0,
		},
		{
			input:    "49",
			expected: 49,
		},
		{
			input:    "-1",
			expected: -1,
		},
	} {
		actual, err :=
			parseSORPostgreSQLDatabasePSQLInt(
				testCase.input,
			)
		if err != nil {
			t.Fatalf(
				"parse %q: %v",
				testCase.input,
				err,
			)
		}

		if actual !=
			testCase.expected {
			t.Fatalf(
				"parse %q = %d, want %d",
				testCase.input,
				actual,
				testCase.expected,
			)
		}
	}

	for _, invalid := range []string{
		"",
		"+1",
		"01",
		"-0",
		"1.0",
		"one",
	} {
		if _, err :=
			parseSORPostgreSQLDatabasePSQLInt(
				invalid,
			); err == nil {
			t.Fatalf(
				"non-canonical PostgreSQL integer %q accepted",
				invalid,
			)
		}
	}
}
