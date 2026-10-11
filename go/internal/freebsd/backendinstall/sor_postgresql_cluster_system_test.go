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

func testSORInitializerJLSAbsent(
	jailName string,
) ([]byte, error) {
	return []byte(
			"jls: jail \"" +
				jailName +
				"\" not found\n" +
				"   JID  IP Address      Hostname                      Path\n",
		), errors.New(
			"exit status 1",
		)
}

func TestSystemSORPostgreSQLClusterInitializerExactCommands(
	t *testing.T,
) {
	commands := make(
		[][]string,
		0,
	)

	jlsChecks := 0

	initializer :=
		systemSORPostgreSQLClusterInitializer{
			execute: func(
				path string,
				args ...string,
			) ([]byte, error) {
				command := append(
					[]string{
						path,
					},
					args...,
				)

				commands = append(
					commands,
					command,
				)

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

				if path ==
					"/usr/local/bin/pg_controldata" {
					t.Fatal(
						"pg_controldata must execute through jexec",
					)
				}

				if path == "/usr/sbin/jexec" &&
					len(args) == 3 &&
					args[1] ==
						"/usr/local/bin/pg_controldata" {
					return []byte(
						"Database cluster state: shut down\n" +
							"Database block size: 8192\n" +
							"Data page checksum version: 1\n",
					), nil
				}

				return nil, nil
			},
		}

	if err := initializer.Initialize(); err != nil {
		t.Fatalf(
			"Initialize() error = %v",
			err,
		)
	}

	expected := [][]string{
		{
			"/usr/sbin/jls",
			"-j",
			"fi-sor-db",
		},
		{
			"/usr/sbin/jls",
			"-j",
			"fi-ingest",
		},
		{
			"/usr/sbin/jls",
			"-j",
			"fi-receiver",
		},
		{
			"/usr/local/etc/rc.d/fi_pf",
			"onestatus",
		},
		{
			"/etc/rc.d/jail",
			"onestart",
			"fi-sor-db",
		},
		{
			"/usr/sbin/jls",
			"-j",
			"fi-sor-db",
		},
		{
			"/usr/sbin/jexec",
			"fi-sor-db",
			"/usr/sbin/service",
			"postgresql",
			"oneinitdb",
		},
		{
			"/usr/sbin/jexec",
			"fi-sor-db",
			"/usr/local/bin/pg_controldata",
			"/var/db/fi/sor/postgres",
		},
		{
			"/etc/rc.d/jail",
			"onestop",
			"fi-sor-db",
		},
		{
			"/usr/sbin/jls",
			"-j",
			"fi-sor-db",
		},
	}

	if !reflect.DeepEqual(
		commands,
		expected,
	) {
		t.Fatalf(
			"commands differ:\nactual=%v\nexpected=%v",
			commands,
			expected,
		)
	}
}

func TestSystemSORPostgreSQLClusterInitializerRejectsRunningJail(
	t *testing.T,
) {
	mutationExecuted := false

	initializer :=
		systemSORPostgreSQLClusterInitializer{
			execute: func(
				path string,
				args ...string,
			) ([]byte, error) {
				if path == "/usr/sbin/jls" &&
					len(args) == 2 &&
					args[1] == "fi-ingest" {
					return []byte(
							"jid=8 name=fi-ingest\n",
						),
						nil
				}

				if path == "/usr/sbin/jls" {
					return testSORInitializerJLSAbsent(
						args[1],
					)
				}

				mutationExecuted = true

				return nil, nil
			},
		}

	err := initializer.Initialize()
	if err == nil {
		t.Fatal(
			"Initialize() accepted running FI jail",
		)
	}

	if !strings.Contains(
		err.Error(),
		"fi-ingest is running",
	) {
		t.Fatalf(
			"unexpected error = %v",
			err,
		)
	}

	if mutationExecuted {
		t.Fatal(
			"mutation executed with FI jail running",
		)
	}
}

func TestSystemSORPostgreSQLClusterInitializerStopsSORAfterInitFailure(
	t *testing.T,
) {
	stopped := false
	jlsChecks := 0

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
					len(args) >= 4 &&
					args[1] == "/usr/sbin/service" {
					return []byte(
							"initdb failed\n",
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
			"Initialize() expected oneinitdb failure",
		)
	}

	if !strings.Contains(
		err.Error(),
		"initdb failed",
	) {
		t.Fatalf(
			"unexpected error = %v",
			err,
		)
	}

	if !stopped {
		t.Fatal(
			"fi-sor-db was not stopped after oneinitdb failure",
		)
	}
}

func TestSystemSORPostgreSQLClusterInitializerRejectsAmbiguousJLSFailure(
	t *testing.T,
) {
	initializer :=
		systemSORPostgreSQLClusterInitializer{
			execute: func(
				path string,
				_ ...string,
			) ([]byte, error) {
				if path == "/usr/sbin/jls" {
					return []byte(
							"permission denied\n",
						),
						errors.New(
							"exit status 1",
						)
				}

				return nil, nil
			},
		}

	err := initializer.Initialize()
	if err == nil {
		t.Fatal(
			"Initialize() accepted ambiguous jls failure",
		)
	}

	if !strings.Contains(
		err.Error(),
		"cannot prove fi-sor-db is stopped",
	) {
		t.Fatalf(
			"unexpected error = %v",
			err,
		)
	}
}
