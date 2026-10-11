// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

type testSystemSORPostgreSQLDatabaseRuntime struct {
	commands       []string
	failPF         bool
	failPostgreSQL bool
	failStop       bool
	running        bool
}

func TestSystemSORPostgreSQLDatabaseObserverExactLifecycle(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	runtime :=
		testSystemSORPostgreSQLDatabaseRuntime{}

	expectedObservation :=
		testSystemSORPostgreSQLDatabaseOwnedMatchObservation()

	observer :=
		systemSORPostgreSQLDatabaseObserver{
			buildPolicy: func(
				Config,
			) (
				sorPostgreSQLDatabasePolicy,
				error,
			) {
				return policy,
					nil
			},

			execute: runtime.execute,

			verifySubstrate: func(
				Config,
			) error {
				runtime.commands =
					append(
						runtime.commands,
						"SUBSTRATE",
					)

				return nil
			},

			observe: func(
				observedPolicy sorPostgreSQLDatabasePolicy,
			) (
				sorPostgreSQLDatabaseObservation,
				sorPostgreSQLDatabaseState,
				error,
			) {
				runtime.commands =
					append(
						runtime.commands,
						"OBSERVE",
					)

				if !runtime.running {
					t.Fatal(
						"semantic observer ran while fi-sor-db was stopped",
					)
				}

				if observedPolicy.DatabaseName !=
					policy.DatabaseName {
					t.Fatalf(
						"database policy = %q, want %q",
						observedPolicy.DatabaseName,
						policy.DatabaseName,
					)
				}

				return expectedObservation,
					sorPostgreSQLDatabaseOwnedMatch,
					nil
			},
		}

	observation,
		state,
		err :=
		observer.Observe(
			Config{},
		)
	if err != nil {
		t.Fatalf(
			"Observe() error = %v",
			err,
		)
	}

	if runtime.running {
		t.Fatal(
			"fi-sor-db remained running after observation",
		)
	}

	if state !=
		sorPostgreSQLDatabaseOwnedMatch {
		t.Fatalf(
			"state = %s, want OWNED_MATCH",
			state,
		)
	}

	if observation !=
		expectedObservation {
		t.Fatalf(
			"observation = %#v, want %#v",
			observation,
			expectedObservation,
		)
	}

	expectedCommands :=
		[]string{
			"/usr/sbin/jls -j fi-sor-db",
			"/usr/sbin/jls -j fi-ingest",
			"/usr/sbin/jls -j fi-receiver",
			"SUBSTRATE",
			"/usr/local/etc/rc.d/fi_pf onestatus",
			"/etc/rc.d/jail onestart fi-sor-db",
			"/usr/sbin/jls -j fi-sor-db",
			"/usr/sbin/jexec fi-sor-db /usr/sbin/service postgresql onestatus",
			"OBSERVE",
			"/etc/rc.d/jail onestop fi-sor-db",
			"/usr/sbin/jls -j fi-sor-db",
		}

	if !reflect.DeepEqual(
		runtime.commands,
		expectedCommands,
	) {
		t.Fatalf(
			"commands = %#v, want %#v",
			runtime.commands,
			expectedCommands,
		)
	}
}

func TestSystemSORPostgreSQLDatabaseObserverRejectsRunningJail(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	runtime :=
		testSystemSORPostgreSQLDatabaseRuntime{
			running: true,
		}

	substrateCalls := 0
	observeCalls := 0

	observer :=
		systemSORPostgreSQLDatabaseObserver{
			buildPolicy: func(
				Config,
			) (
				sorPostgreSQLDatabasePolicy,
				error,
			) {
				return policy,
					nil
			},

			execute: runtime.execute,

			verifySubstrate: func(
				Config,
			) error {
				substrateCalls++

				return nil
			},

			observe: func(
				sorPostgreSQLDatabasePolicy,
			) (
				sorPostgreSQLDatabaseObservation,
				sorPostgreSQLDatabaseState,
				error,
			) {
				observeCalls++

				return testSystemSORPostgreSQLDatabaseOwnedMatchObservation(),
					sorPostgreSQLDatabaseOwnedMatch,
					nil
			},
		}

	_,
		state,
		err :=
		observer.Observe(
			Config{},
		)

	if err == nil {
		t.Fatal(
			"running FI jail was accepted",
		)
	}

	if state !=
		sorPostgreSQLDatabaseUnknown {
		t.Fatalf(
			"state = %s, want UNKNOWN",
			state,
		)
	}

	if substrateCalls != 0 {
		t.Fatalf(
			"substrate verification ran after running-jail detection: %d",
			substrateCalls,
		)
	}

	if observeCalls != 0 {
		t.Fatalf(
			"semantic observation ran after running-jail detection: %d",
			observeCalls,
		)
	}
}

func TestSystemSORPostgreSQLDatabaseObserverSubstrateFailureStopsBeforeStart(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	runtime :=
		testSystemSORPostgreSQLDatabaseRuntime{}

	observeCalls := 0

	observer :=
		systemSORPostgreSQLDatabaseObserver{
			buildPolicy: func(
				Config,
			) (
				sorPostgreSQLDatabasePolicy,
				error,
			) {
				return policy,
					nil
			},

			execute: runtime.execute,

			verifySubstrate: func(
				Config,
			) error {
				return errors.New(
					"synthetic substrate failure",
				)
			},

			observe: func(
				sorPostgreSQLDatabasePolicy,
			) (
				sorPostgreSQLDatabaseObservation,
				sorPostgreSQLDatabaseState,
				error,
			) {
				observeCalls++

				return sorPostgreSQLDatabaseObservation{},
					sorPostgreSQLDatabaseOwnedMatch,
					nil
			},
		}

	_,
		state,
		err :=
		observer.Observe(
			Config{},
		)

	if err == nil {
		t.Fatal(
			"substrate failure was accepted",
		)
	}

	if state !=
		sorPostgreSQLDatabaseUnknown {
		t.Fatalf(
			"state = %s, want UNKNOWN",
			state,
		)
	}

	if runtime.running {
		t.Fatal(
			"fi-sor-db started after substrate failure",
		)
	}

	if observeCalls != 0 {
		t.Fatalf(
			"semantic observation ran after substrate failure: %d",
			observeCalls,
		)
	}

	for _, command := range runtime.commands {
		if strings.Contains(
			command,
			"onestart",
		) {
			t.Fatalf(
				"jail start executed after substrate failure: %s",
				command,
			)
		}
	}
}

func TestSystemSORPostgreSQLDatabaseObserverPFFailureStopsBeforeStart(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	runtime :=
		testSystemSORPostgreSQLDatabaseRuntime{
			failPF: true,
		}

	observeCalls := 0

	observer :=
		systemSORPostgreSQLDatabaseObserver{
			buildPolicy: func(
				Config,
			) (
				sorPostgreSQLDatabasePolicy,
				error,
			) {
				return policy,
					nil
			},

			execute: runtime.execute,

			verifySubstrate: func(
				Config,
			) error {
				return nil
			},

			observe: func(
				sorPostgreSQLDatabasePolicy,
			) (
				sorPostgreSQLDatabaseObservation,
				sorPostgreSQLDatabaseState,
				error,
			) {
				observeCalls++

				return sorPostgreSQLDatabaseObservation{},
					sorPostgreSQLDatabaseOwnedMatch,
					nil
			},
		}

	_,
		state,
		err :=
		observer.Observe(
			Config{},
		)

	if err == nil {
		t.Fatal(
			"PF runtime failure was accepted",
		)
	}

	if state !=
		sorPostgreSQLDatabaseUnknown {
		t.Fatalf(
			"state = %s, want UNKNOWN",
			state,
		)
	}

	if runtime.running {
		t.Fatal(
			"fi-sor-db started after PF runtime failure",
		)
	}

	if observeCalls != 0 {
		t.Fatalf(
			"semantic observation ran after PF runtime failure: %d",
			observeCalls,
		)
	}
}

func TestSystemSORPostgreSQLDatabaseObserverPostgreSQLRuntimeFailureCleansUp(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	runtime :=
		testSystemSORPostgreSQLDatabaseRuntime{
			failPostgreSQL: true,
		}

	observeCalls := 0

	observer :=
		systemSORPostgreSQLDatabaseObserver{
			buildPolicy: func(
				Config,
			) (
				sorPostgreSQLDatabasePolicy,
				error,
			) {
				return policy,
					nil
			},

			execute: runtime.execute,

			verifySubstrate: func(
				Config,
			) error {
				return nil
			},

			observe: func(
				sorPostgreSQLDatabasePolicy,
			) (
				sorPostgreSQLDatabaseObservation,
				sorPostgreSQLDatabaseState,
				error,
			) {
				observeCalls++

				return sorPostgreSQLDatabaseObservation{},
					sorPostgreSQLDatabaseOwnedMatch,
					nil
			},
		}

	_,
		state,
		err :=
		observer.Observe(
			Config{},
		)

	if err == nil {
		t.Fatal(
			"PostgreSQL runtime failure was accepted",
		)
	}

	if state !=
		sorPostgreSQLDatabaseUnknown {
		t.Fatalf(
			"state = %s, want UNKNOWN",
			state,
		)
	}

	if runtime.running {
		t.Fatal(
			"fi-sor-db remained running after PostgreSQL runtime failure",
		)
	}

	if observeCalls != 0 {
		t.Fatalf(
			"semantic observation ran after PostgreSQL runtime failure: %d",
			observeCalls,
		)
	}

	if !testSystemSORPostgreSQLDatabaseCommandObserved(
		runtime.commands,
		"/etc/rc.d/jail onestop fi-sor-db",
	) {
		t.Fatal(
			"PostgreSQL runtime failure did not trigger SOR cleanup",
		)
	}
}

func TestSystemSORPostgreSQLDatabaseObserverSemanticFailureCleansUp(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	runtime :=
		testSystemSORPostgreSQLDatabaseRuntime{}

	observer :=
		systemSORPostgreSQLDatabaseObserver{
			buildPolicy: func(
				Config,
			) (
				sorPostgreSQLDatabasePolicy,
				error,
			) {
				return policy,
					nil
			},

			execute: runtime.execute,

			verifySubstrate: func(
				Config,
			) error {
				return nil
			},

			observe: func(
				sorPostgreSQLDatabasePolicy,
			) (
				sorPostgreSQLDatabaseObservation,
				sorPostgreSQLDatabaseState,
				error,
			) {
				return sorPostgreSQLDatabaseObservation{},
					sorPostgreSQLDatabaseUnknown,
					errors.New(
						"synthetic semantic failure",
					)
			},
		}

	_,
		state,
		err :=
		observer.Observe(
			Config{},
		)

	if err == nil {
		t.Fatal(
			"semantic observation failure was accepted",
		)
	}

	if state !=
		sorPostgreSQLDatabaseUnknown {
		t.Fatalf(
			"state = %s, want UNKNOWN",
			state,
		)
	}

	if runtime.running {
		t.Fatal(
			"fi-sor-db remained running after semantic failure",
		)
	}

	if !testSystemSORPostgreSQLDatabaseCommandObserved(
		runtime.commands,
		"/etc/rc.d/jail onestop fi-sor-db",
	) {
		t.Fatal(
			"semantic failure did not trigger SOR cleanup",
		)
	}
}

func TestSystemSORPostgreSQLDatabaseObserverCleanupFailureForcesUnknown(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	runtime :=
		testSystemSORPostgreSQLDatabaseRuntime{
			failStop: true,
		}

	observer :=
		systemSORPostgreSQLDatabaseObserver{
			buildPolicy: func(
				Config,
			) (
				sorPostgreSQLDatabasePolicy,
				error,
			) {
				return policy,
					nil
			},

			execute: runtime.execute,

			verifySubstrate: func(
				Config,
			) error {
				return nil
			},

			observe: func(
				sorPostgreSQLDatabasePolicy,
			) (
				sorPostgreSQLDatabaseObservation,
				sorPostgreSQLDatabaseState,
				error,
			) {
				return testSystemSORPostgreSQLDatabaseOwnedMatchObservation(),
					sorPostgreSQLDatabaseOwnedMatch,
					nil
			},
		}

	_,
		state,
		err :=
		observer.Observe(
			Config{},
		)

	if err == nil {
		t.Fatal(
			"cleanup failure was accepted",
		)
	}

	if state !=
		sorPostgreSQLDatabaseUnknown {
		t.Fatalf(
			"cleanup failure state = %s, want UNKNOWN",
			state,
		)
	}

	if !runtime.running {
		t.Fatal(
			"synthetic failed cleanup unexpectedly marked SOR stopped",
		)
	}

	if !strings.Contains(
		err.Error(),
		"emergency PostgreSQL database observation cleanup",
	) {
		t.Fatalf(
			"cleanup error = %q",
			err,
		)
	}
}

func (
	runtime *testSystemSORPostgreSQLDatabaseRuntime,
) execute(
	path string,
	args ...string,
) ([]byte, error) {
	command :=
		strings.TrimSpace(
			path + " " +
				strings.Join(
					args,
					" ",
				),
		)

	runtime.commands =
		append(
			runtime.commands,
			command,
		)

	switch path {
	case "/usr/sbin/jls":
		if len(args) != 2 ||
			args[0] != "-j" {
			return nil,
				fmt.Errorf(
					"unexpected jls arguments: %v",
					args,
				)
		}

		jailName :=
			args[1]

		if jailName == "fi-sor-db" &&
			runtime.running {
			return []byte(
					"fi-sor-db running\n",
				),
				nil
		}

		return testSORInitializerJLSAbsent(
			jailName,
		)

	case "/usr/local/etc/rc.d/fi_pf":
		if len(args) != 1 ||
			args[0] != "onestatus" {
			return nil,
				fmt.Errorf(
					"unexpected fi_pf arguments: %v",
					args,
				)
		}

		if runtime.failPF {
			return []byte(
					"fi_pf not ready\n",
				),
				errors.New(
					"exit status 1",
				)
		}

		return nil,
			nil

	case "/etc/rc.d/jail":
		if len(args) != 2 ||
			args[1] != "fi-sor-db" {
			return nil,
				fmt.Errorf(
					"unexpected jail arguments: %v",
					args,
				)
		}

		switch args[0] {
		case "onestart":
			if runtime.running {
				return nil,
					errors.New(
						"fi-sor-db already running",
					)
			}

			runtime.running =
				true

			return nil,
				nil

		case "onestop":
			if runtime.failStop {
				return []byte(
						"synthetic stop failure\n",
					),
					errors.New(
						"exit status 1",
					)
			}

			runtime.running =
				false

			return nil,
				nil

		default:
			return nil,
				fmt.Errorf(
					"unexpected jail operation: %v",
					args,
				)
		}

	case "/usr/sbin/jexec":
		if len(args) != 4 ||
			args[0] != "fi-sor-db" ||
			args[1] != "/usr/sbin/service" ||
			args[2] != "postgresql" ||
			args[3] != "onestatus" {
			return nil,
				fmt.Errorf(
					"unexpected jexec arguments: %v",
					args,
				)
		}

		if !runtime.running {
			return nil,
				errors.New(
					"fi-sor-db is stopped",
				)
		}

		if runtime.failPostgreSQL {
			return []byte(
					"postgresql is not running\n",
				),
				errors.New(
					"exit status 1",
				)
		}

		return nil,
			nil
	}

	return nil,
		fmt.Errorf(
			"unexpected command: %s",
			command,
		)
}

func testSystemSORPostgreSQLDatabaseCommandObserved(
	commands []string,
	expected string,
) bool {
	for _, command := range commands {
		if command == expected {
			return true
		}
	}

	return false
}

func testSystemSORPostgreSQLDatabaseOwnedMatchObservation() sorPostgreSQLDatabaseObservation {
	return sorPostgreSQLDatabaseObservation{
		OwnerRole: sorPostgreSQLDatabaseResourceOwnedMatch,

		IngestRole: sorPostgreSQLDatabaseResourceOwnedMatch,

		Database: sorPostgreSQLDatabaseResourceOwnedMatch,

		Schema: sorPostgreSQLDatabaseResourceOwnedMatch,

		RelationalFoundation: sorPostgreSQLDatabaseResourceOwnedMatch,

		Privileges: sorPostgreSQLDatabaseResourceOwnedMatch,

		Credential: sorPostgreSQLDatabaseResourceOwnedMatch,

		Passfile: sorPostgreSQLDatabaseResourceOwnedMatch,
	}
}
