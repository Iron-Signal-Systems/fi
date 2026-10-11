// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"errors"
	"strings"
	"testing"
)

func TestRequireSORInitializerPFRuntimeReadyExactCommand(
	t *testing.T,
) {
	calls := 0

	err := requireSORInitializerPFRuntimeReady(
		func(
			path string,
			args ...string,
		) ([]byte, error) {
			calls++

			if path !=
				"/usr/local/etc/rc.d/fi_pf" {
				t.Fatalf(
					"path = %q",
					path,
				)
			}

			if len(args) != 1 ||
				args[0] != "onestatus" {
				t.Fatalf(
					"args = %v",
					args,
				)
			}

			return nil, nil
		},
	)

	if err != nil {
		t.Fatalf(
			"requireSORInitializerPFRuntimeReady() error = %v",
			err,
		)
	}

	if calls != 1 {
		t.Fatalf(
			"execute calls = %d, want 1",
			calls,
		)
	}
}

func TestSystemSORPostgreSQLClusterInitializerRejectsPFNotReady(
	t *testing.T,
) {
	jlsChecks := 0
	jailStartCalled := false

	initializer :=
		systemSORPostgreSQLClusterInitializer{
			execute: func(
				path string,
				args ...string,
			) ([]byte, error) {
				if path == "/usr/sbin/jls" {
					jlsChecks++

					return testSORInitializerJLSAbsent(
						args[1],
					)
				}

				if path ==
					"/usr/local/etc/rc.d/fi_pf" {
					if len(args) != 1 ||
						args[0] != "onestatus" {
						t.Fatalf(
							"unexpected fi_pf args = %v",
							args,
						)
					}

					return []byte(
							"FI PF runtime not ready\n",
						),
						errors.New(
							"exit status 1",
						)
				}

				if path == "/etc/rc.d/jail" &&
					len(args) >= 1 &&
					args[0] == "onestart" {
					jailStartCalled = true
				}

				return nil, nil
			},
		}

	err := initializer.Initialize()
	if err == nil {
		t.Fatal(
			"Initialize() accepted unavailable FI PF runtime",
		)
	}

	if !strings.Contains(
		err.Error(),
		"FI PF runtime is not ready",
	) {
		t.Fatalf(
			"PF readiness context missing: %v",
			err,
		)
	}

	if !strings.Contains(
		err.Error(),
		"FI PF runtime not ready",
	) {
		t.Fatalf(
			"PF readiness output missing: %v",
			err,
		)
	}

	if jailStartCalled {
		t.Fatal(
			"fi-sor-db start attempted without FI PF readiness",
		)
	}

	if jlsChecks != 3 {
		t.Fatalf(
			"jls checks = %d, want 3",
			jlsChecks,
		)
	}
}

func TestVerifySORPostgreSQLInitializationSubstrateOrder(
	t *testing.T,
) {
	calls := make(
		[]string,
		0,
		5,
	)

	verifiers :=
		testSORPostgreSQLInitializationSubstrateVerifiers(
			&calls,
			"",
		)

	err := verifySORPostgreSQLInitializationSubstrateWith(
		Config{},
		verifiers,
	)
	if err != nil {
		t.Fatalf(
			"verifySORPostgreSQLInitializationSubstrateWith() error = %v",
			err,
		)
	}

	actual := strings.Join(
		calls,
		",",
	)

	const expected = "devfs,host-files,host-network,pf,lifecycle"

	if actual != expected {
		t.Fatalf(
			"verification order = %q, want %q",
			actual,
			expected,
		)
	}
}

func TestVerifySORPostgreSQLInitializationSubstrateFailsClosed(
	t *testing.T,
) {
	tests := []struct {
		FailAt          string
		ExpectedCalls   string
		ExpectedContext string
	}{
		{
			FailAt:          "devfs",
			ExpectedCalls:   "devfs",
			ExpectedContext: "devfs prerequisite failed",
		},
		{
			FailAt:          "host-files",
			ExpectedCalls:   "devfs,host-files",
			ExpectedContext: "host-file prerequisite failed",
		},
		{
			FailAt:          "host-network",
			ExpectedCalls:   "devfs,host-files,host-network",
			ExpectedContext: "host-network prerequisite failed",
		},
		{
			FailAt:          "pf",
			ExpectedCalls:   "devfs,host-files,host-network,pf",
			ExpectedContext: "persistent PF prerequisite failed",
		},
		{
			FailAt:          "lifecycle",
			ExpectedCalls:   "devfs,host-files,host-network,pf,lifecycle",
			ExpectedContext: "lifecycle prerequisite failed",
		},
	}

	for _, test := range tests {
		test := test

		t.Run(
			test.FailAt,
			func(t *testing.T) {
				calls := make(
					[]string,
					0,
					5,
				)

				verifiers :=
					testSORPostgreSQLInitializationSubstrateVerifiers(
						&calls,
						test.FailAt,
					)

				err :=
					verifySORPostgreSQLInitializationSubstrateWith(
						Config{},
						verifiers,
					)

				if err == nil {
					t.Fatal(
						"substrate verification unexpectedly succeeded",
					)
				}

				if !strings.Contains(
					err.Error(),
					test.ExpectedContext,
				) {
					t.Fatalf(
						"error = %q, want context %q",
						err,
						test.ExpectedContext,
					)
				}

				if !strings.Contains(
					err.Error(),
					"test substrate failure",
				) {
					t.Fatalf(
						"underlying error missing: %v",
						err,
					)
				}

				actual := strings.Join(
					calls,
					",",
				)

				if actual !=
					test.ExpectedCalls {
					t.Fatalf(
						"calls = %q, want %q",
						actual,
						test.ExpectedCalls,
					)
				}
			},
		)
	}
}

func testSORPostgreSQLInitializationSubstrateVerifiers(
	calls *[]string,
	failAt string,
) sorPostgreSQLInitializationSubstrateVerifiers {
	verifier := func(
		name string,
	) func(Config) error {
		return func(
			Config,
		) error {
			*calls = append(
				*calls,
				name,
			)

			if name == failAt {
				return errors.New(
					"test substrate failure",
				)
			}

			return nil
		}
	}

	return sorPostgreSQLInitializationSubstrateVerifiers{
		Devfs:       verifier("devfs"),
		HostFiles:   verifier("host-files"),
		HostNetwork: verifier("host-network"),
		Lifecycle:   verifier("lifecycle"),
		PFPolicy:    verifier("pf"),
	}
}
