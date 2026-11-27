// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"errors"
	"strings"
	"testing"
)

func TestSystemSORPostgreSQLClusterInitializerAcceptsRealJLSAbsentSignature(
	t *testing.T,
) {
	for _, jailName := range []string{
		"fi-sor-db",
		"fi-ingest",
		"fi-receiver",
	} {
		output, expectedErr :=
			testSORInitializerJLSAbsent(
				jailName,
			)

		stopped, err :=
			inspectSORInitializerJailStopped(
				func(
					path string,
					args ...string,
				) ([]byte, error) {
					if path != "/usr/sbin/jls" {
						t.Fatalf(
							"unexpected command: %s %v",
							path,
							args,
						)
					}

					return output,
						expectedErr
				},
				jailName,
			)

		if err != nil {
			t.Fatalf(
				"%s stopped inspection error = %v",
				jailName,
				err,
			)
		}

		if !stopped {
			t.Fatalf(
				"%s was not classified stopped",
				jailName,
			)
		}
	}
}

func TestSystemSORPostgreSQLClusterInitializerRejectsWrongJLSAbsentName(
	t *testing.T,
) {
	output, expectedErr :=
		testSORInitializerJLSAbsent(
			"some-other-jail",
		)

	stopped, err :=
		inspectSORInitializerJailStopped(
			func(
				_ string,
				_ ...string,
			) ([]byte, error) {
				return output,
					expectedErr
			},
			"fi-sor-db",
		)

	if err == nil {
		t.Fatal(
			"wrong-name jls signature was accepted",
		)
	}

	if stopped {
		t.Fatal(
			"wrong-name jls signature classified stopped",
		)
	}
}

func TestSystemSORPostgreSQLClusterInitializerRejectsEmptyJLSFailure(
	t *testing.T,
) {
	stopped, err :=
		inspectSORInitializerJailStopped(
			func(
				_ string,
				_ ...string,
			) ([]byte, error) {
				return nil,
					errors.New(
						"exit status 1",
					)
			},
			"fi-sor-db",
		)

	if err == nil {
		t.Fatal(
			"empty jls failure was accepted as stopped",
		)
	}

	if stopped {
		t.Fatal(
			"empty jls failure classified stopped",
		)
	}
}

func TestSystemSORPostgreSQLClusterInitializerPropagatesEmergencyStopFailure(
	t *testing.T,
) {
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

					return []byte(
						"jid=9 name=fi-sor-db\n",
					), nil
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
					return []byte(
							"stop failed\n",
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
			"Initialize() accepted init failure plus cleanup failure",
		)
	}

	if !strings.Contains(
		err.Error(),
		"initdb failed",
	) {
		t.Fatalf(
			"primary failure missing: %v",
			err,
		)
	}

	if !strings.Contains(
		err.Error(),
		"emergency PostgreSQL initialization cleanup",
	) {
		t.Fatalf(
			"cleanup failure missing: %v",
			err,
		)
	}

	if !strings.Contains(
		err.Error(),
		"stop failed",
	) {
		t.Fatalf(
			"stop failure detail missing: %v",
			err,
		)
	}
}

func TestSystemSORPostgreSQLClusterInitializerRejectsStopThatLeavesJailRunning(
	t *testing.T,
) {
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

					return []byte(
						"jid=9 name=fi-sor-db\n",
					), nil
				}

				return nil, nil
			},
		}

	err := initializer.Initialize()
	if err == nil {
		t.Fatal(
			"Initialize() accepted stop that left jail running",
		)
	}

	if !strings.Contains(
		err.Error(),
		"fi-sor-db remained running",
	) {
		t.Fatalf(
			"unexpected error = %v",
			err,
		)
	}
}
