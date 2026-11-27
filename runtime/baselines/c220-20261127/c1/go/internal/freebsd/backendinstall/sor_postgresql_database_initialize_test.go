// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"errors"
	"strings"
	"testing"
)

func TestInitializeSORPostgreSQLDatabaseOwnedMatchIsNoOp(
	t *testing.T,
) {
	observeCalls := 0
	initializeCalls := 0

	err :=
		initializeSORPostgreSQLDatabaseWith(
			func() (
				sorPostgreSQLDatabaseObservation,
				sorPostgreSQLDatabaseState,
				error,
			) {
				observeCalls++

				return sorPostgreSQLDatabaseObservation{},
					sorPostgreSQLDatabaseOwnedMatch,
					nil
			},
			func() error {
				initializeCalls++

				return nil
			},
		)
	if err != nil {
		t.Fatalf(
			"initialize database: %v",
			err,
		)
	}

	if observeCalls != 1 {
		t.Fatalf(
			"observer calls = %d, want 1",
			observeCalls,
		)
	}

	if initializeCalls != 0 {
		t.Fatalf(
			"initializer calls = %d, want 0",
			initializeCalls,
		)
	}
}

func TestInitializeSORPostgreSQLDatabaseAbsentInitializesToOwnedMatch(
	t *testing.T,
) {
	observeCalls := 0
	initializeCalls := 0

	err :=
		initializeSORPostgreSQLDatabaseWith(
			func() (
				sorPostgreSQLDatabaseObservation,
				sorPostgreSQLDatabaseState,
				error,
			) {
				observeCalls++

				if observeCalls == 1 {
					return sorPostgreSQLDatabaseObservation{},
						sorPostgreSQLDatabaseAbsent,
						nil
				}

				return sorPostgreSQLDatabaseObservation{},
					sorPostgreSQLDatabaseOwnedMatch,
					nil
			},
			func() error {
				initializeCalls++

				return nil
			},
		)
	if err != nil {
		t.Fatalf(
			"initialize database: %v",
			err,
		)
	}

	if observeCalls != 2 {
		t.Fatalf(
			"observer calls = %d, want 2",
			observeCalls,
		)
	}

	if initializeCalls != 1 {
		t.Fatalf(
			"initializer calls = %d, want 1",
			initializeCalls,
		)
	}
}

func TestInitializeSORPostgreSQLDatabaseRejectsUnsafeInitialState(
	t *testing.T,
) {
	tests :=
		[]struct {
			name  string
			state sorPostgreSQLDatabaseState
		}{
			{
				name:  "owned drift",
				state: sorPostgreSQLDatabaseOwnedDrift,
			},
			{
				name:  "foreign collision",
				state: sorPostgreSQLDatabaseForeignCollision,
			},
			{
				name:  "unknown",
				state: sorPostgreSQLDatabaseUnknown,
			},
			{
				name: "unrecognized",
				state: sorPostgreSQLDatabaseState(
					"SYNTHETIC_INVALID",
				),
			},
		}

	for _, test := range tests {
		t.Run(
			test.name,
			func(
				t *testing.T,
			) {
				initializeCalls := 0

				err :=
					initializeSORPostgreSQLDatabaseWith(
						func() (
							sorPostgreSQLDatabaseObservation,
							sorPostgreSQLDatabaseState,
							error,
						) {
							return sorPostgreSQLDatabaseObservation{},
								test.state,
								nil
						},
						func() error {
							initializeCalls++

							return nil
						},
					)

				if err == nil {
					t.Fatalf(
						"state %q was accepted",
						test.state,
					)
				}

				if initializeCalls != 0 {
					t.Fatalf(
						"initializer ran from state %q: %d",
						test.state,
						initializeCalls,
					)
				}

				if !strings.Contains(
					err.Error(),
					string(test.state),
				) {
					t.Fatalf(
						"error %q does not contain state %q",
						err,
						test.state,
					)
				}
			},
		)
	}
}

func TestInitializeSORPostgreSQLDatabaseInitialObserverFailure(
	t *testing.T,
) {
	initializeCalls := 0

	err :=
		initializeSORPostgreSQLDatabaseWith(
			func() (
				sorPostgreSQLDatabaseObservation,
				sorPostgreSQLDatabaseState,
				error,
			) {
				return sorPostgreSQLDatabaseObservation{},
					sorPostgreSQLDatabaseUnknown,
					errors.New(
						"synthetic initial observer failure",
					)
			},
			func() error {
				initializeCalls++

				return nil
			},
		)

	if err == nil {
		t.Fatal(
			"initial observer failure was accepted",
		)
	}

	if initializeCalls != 0 {
		t.Fatalf(
			"initializer ran after initial observer failure: %d",
			initializeCalls,
		)
	}

	if !strings.Contains(
		err.Error(),
		"observe initial PostgreSQL database state",
	) {
		t.Fatalf(
			"error = %q",
			err,
		)
	}
}

func TestInitializeSORPostgreSQLDatabaseInitializerFailure(
	t *testing.T,
) {
	observeCalls := 0
	initializeCalls := 0

	err :=
		initializeSORPostgreSQLDatabaseWith(
			func() (
				sorPostgreSQLDatabaseObservation,
				sorPostgreSQLDatabaseState,
				error,
			) {
				observeCalls++

				return sorPostgreSQLDatabaseObservation{},
					sorPostgreSQLDatabaseAbsent,
					nil
			},
			func() error {
				initializeCalls++

				return errors.New(
					"synthetic initializer failure",
				)
			},
		)

	if err == nil {
		t.Fatal(
			"initializer failure was accepted",
		)
	}

	if observeCalls != 1 {
		t.Fatalf(
			"observer calls = %d, want 1",
			observeCalls,
		)
	}

	if initializeCalls != 1 {
		t.Fatalf(
			"initializer calls = %d, want 1",
			initializeCalls,
		)
	}

	if !strings.Contains(
		err.Error(),
		"initialize PostgreSQL database",
	) {
		t.Fatalf(
			"error = %q",
			err,
		)
	}
}

func TestInitializeSORPostgreSQLDatabaseFinalObserverFailure(
	t *testing.T,
) {
	observeCalls := 0

	err :=
		initializeSORPostgreSQLDatabaseWith(
			func() (
				sorPostgreSQLDatabaseObservation,
				sorPostgreSQLDatabaseState,
				error,
			) {
				observeCalls++

				if observeCalls == 1 {
					return sorPostgreSQLDatabaseObservation{},
						sorPostgreSQLDatabaseAbsent,
						nil
				}

				return sorPostgreSQLDatabaseObservation{},
					sorPostgreSQLDatabaseUnknown,
					errors.New(
						"synthetic final observer failure",
					)
			},
			func() error {
				return nil
			},
		)

	if err == nil {
		t.Fatal(
			"final observer failure was accepted",
		)
	}

	if observeCalls != 2 {
		t.Fatalf(
			"observer calls = %d, want 2",
			observeCalls,
		)
	}

	if !strings.Contains(
		err.Error(),
		"observe final PostgreSQL database state",
	) {
		t.Fatalf(
			"error = %q",
			err,
		)
	}
}

func TestInitializeSORPostgreSQLDatabaseRequiresFinalOwnedMatch(
	t *testing.T,
) {
	tests :=
		[]struct {
			name  string
			state sorPostgreSQLDatabaseState
		}{
			{
				name:  "absent",
				state: sorPostgreSQLDatabaseAbsent,
			},
			{
				name:  "owned drift",
				state: sorPostgreSQLDatabaseOwnedDrift,
			},
			{
				name:  "foreign collision",
				state: sorPostgreSQLDatabaseForeignCollision,
			},
			{
				name:  "unknown",
				state: sorPostgreSQLDatabaseUnknown,
			},
		}

	for _, test := range tests {
		t.Run(
			test.name,
			func(
				t *testing.T,
			) {
				observeCalls := 0
				initializeCalls := 0

				err :=
					initializeSORPostgreSQLDatabaseWith(
						func() (
							sorPostgreSQLDatabaseObservation,
							sorPostgreSQLDatabaseState,
							error,
						) {
							observeCalls++

							if observeCalls == 1 {
								return sorPostgreSQLDatabaseObservation{},
									sorPostgreSQLDatabaseAbsent,
									nil
							}

							return sorPostgreSQLDatabaseObservation{},
								test.state,
								nil
						},
						func() error {
							initializeCalls++

							return nil
						},
					)

				if err == nil {
					t.Fatalf(
						"final state %s was accepted",
						test.state,
					)
				}

				if observeCalls != 2 {
					t.Fatalf(
						"observer calls = %d, want 2",
						observeCalls,
					)
				}

				if initializeCalls != 1 {
					t.Fatalf(
						"initializer calls = %d, want 1",
						initializeCalls,
					)
				}

				if !strings.Contains(
					err.Error(),
					string(test.state),
				) {
					t.Fatalf(
						"error %q does not contain final state %s",
						err,
						test.state,
					)
				}
			},
		)
	}
}

func TestInitializeSORPostgreSQLDatabaseRequiresCallbacks(
	t *testing.T,
) {
	err :=
		initializeSORPostgreSQLDatabaseWith(
			nil,
			func() error {
				return nil
			},
		)
	if err == nil ||
		!strings.Contains(
			err.Error(),
			"observer is required",
		) {
		t.Fatalf(
			"nil observer error = %v",
			err,
		)
	}

	err =
		initializeSORPostgreSQLDatabaseWith(
			func() (
				sorPostgreSQLDatabaseObservation,
				sorPostgreSQLDatabaseState,
				error,
			) {
				return sorPostgreSQLDatabaseObservation{},
					sorPostgreSQLDatabaseAbsent,
					nil
			},
			nil,
		)
	if err == nil ||
		!strings.Contains(
			err.Error(),
			"initializer is required",
		) {
		t.Fatalf(
			"nil initializer error = %v",
			err,
		)
	}
}
