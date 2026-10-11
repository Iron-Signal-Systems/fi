// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"errors"
	"strings"
	"testing"
)

func TestSystemSORPostgreSQLClusterInitializerRejectsInvalidControlData(
	t *testing.T,
) {
	jlsChecks := 0
	stopped := false

	initializer :=
		systemSORPostgreSQLClusterInitializer{
			execute: func(
				path string,
				args ...string,
			) ([]byte, error) {
				if path == "/usr/sbin/jls" {
					jlsChecks++

					if jlsChecks <= 3 {
						return testSORInitializerJLSAbsent(
							args[1],
						)
					}

					if jlsChecks == 4 {
						return []byte(
							"jid=9 name=fi-sor-db\n",
						), nil
					}

					return testSORInitializerJLSAbsent(
						args[1],
					)
				}

				if path == "/usr/sbin/jexec" &&
					len(args) == 3 &&
					args[1] ==
						"/usr/local/bin/pg_controldata" {
					return []byte(
						"Database cluster state: shut down\n" +
							"Database block size: 8192\n" +
							"Data page checksum version: 0\n",
					), nil
				}

				if path == "/etc/rc.d/jail" &&
					len(args) == 2 &&
					args[0] == "onestop" {
					stopped = true
				}

				return nil, nil
			},
		}

	err := initializer.Initialize()
	if err == nil {
		t.Fatal(
			"Initialize() accepted invalid pg_controldata semantics",
		)
	}

	if !strings.Contains(
		err.Error(),
		"validate PostgreSQL control data",
	) {
		t.Fatalf(
			"semantic validation context missing: %v",
			err,
		)
	}

	if !strings.Contains(
		err.Error(),
		`checksum version = "0"`,
	) {
		t.Fatalf(
			"checksum failure detail missing: %v",
			err,
		)
	}

	if !stopped {
		t.Fatal(
			"fi-sor-db was not stopped after control-data validation failure",
		)
	}
}

func TestSystemSORPostgreSQLClusterInitializerPropagatesControlDataCommandFailure(
	t *testing.T,
) {
	jlsChecks := 0
	stopped := false

	initializer :=
		systemSORPostgreSQLClusterInitializer{
			execute: func(
				path string,
				args ...string,
			) ([]byte, error) {
				if path == "/usr/sbin/jls" {
					jlsChecks++

					if jlsChecks <= 3 {
						return testSORInitializerJLSAbsent(
							args[1],
						)
					}

					if jlsChecks == 4 {
						return []byte(
							"jid=9 name=fi-sor-db\n",
						), nil
					}

					return testSORInitializerJLSAbsent(
						args[1],
					)
				}

				if path == "/usr/sbin/jexec" &&
					len(args) == 3 &&
					args[1] ==
						"/usr/local/bin/pg_controldata" {
					return []byte(
							"pg_controldata failed\n",
						),
						errors.New(
							"exit status 1",
						)
				}

				if path == "/etc/rc.d/jail" &&
					len(args) == 2 &&
					args[0] == "onestop" {
					stopped = true
				}

				return nil, nil
			},
		}

	err := initializer.Initialize()
	if err == nil {
		t.Fatal(
			"Initialize() accepted pg_controldata command failure",
		)
	}

	if !strings.Contains(
		err.Error(),
		"verify PostgreSQL control data",
	) {
		t.Fatalf(
			"command failure context missing: %v",
			err,
		)
	}

	if !strings.Contains(
		err.Error(),
		"pg_controldata failed",
	) {
		t.Fatalf(
			"command output missing: %v",
			err,
		)
	}

	if !stopped {
		t.Fatal(
			"fi-sor-db was not stopped after pg_controldata command failure",
		)
	}
}
