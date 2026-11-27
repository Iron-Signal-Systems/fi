// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"errors"
	"strings"
	"testing"
)

func TestVerifySORPostgreSQLDatabaseOwnedMatch(
	t *testing.T,
) {
	clusterCalls := 0
	observerCalls := 0

	err :=
		verifySORPostgreSQLDatabaseWith(
			Config{},
			func(
				Config,
			) error {
				clusterCalls++

				return nil
			},
			func(
				Config,
			) (
				sorPostgreSQLDatabaseObservation,
				sorPostgreSQLDatabaseState,
				error,
			) {
				observerCalls++

				return sorPostgreSQLDatabaseObservation{},
					sorPostgreSQLDatabaseOwnedMatch,
					nil
			},
		)
	if err != nil {
		t.Fatalf(
			"verify database: %v",
			err,
		)
	}

	if clusterCalls != 1 {
		t.Fatalf(
			"cluster verifier calls = %d, want 1",
			clusterCalls,
		)
	}

	if observerCalls != 1 {
		t.Fatalf(
			"database observer calls = %d, want 1",
			observerCalls,
		)
	}
}

func TestVerifySORPostgreSQLDatabaseClusterFailureStopsBeforeObservation(
	t *testing.T,
) {
	observerCalls := 0

	err :=
		verifySORPostgreSQLDatabaseWith(
			Config{},
			func(
				Config,
			) error {
				return errors.New(
					"synthetic cluster failure",
				)
			},
			func(
				Config,
			) (
				sorPostgreSQLDatabaseObservation,
				sorPostgreSQLDatabaseState,
				error,
			) {
				observerCalls++

				return sorPostgreSQLDatabaseObservation{},
					sorPostgreSQLDatabaseOwnedMatch,
					nil
			},
		)

	if err == nil {
		t.Fatal(
			"cluster prerequisite failure was accepted",
		)
	}

	if observerCalls != 0 {
		t.Fatalf(
			"database observer ran after cluster failure: %d",
			observerCalls,
		)
	}

	if !strings.Contains(
		err.Error(),
		"cluster prerequisite failed",
	) {
		t.Fatalf(
			"error = %q",
			err,
		)
	}
}

func TestVerifySORPostgreSQLDatabaseObserverFailure(
	t *testing.T,
) {
	err :=
		verifySORPostgreSQLDatabaseWith(
			Config{},
			func(
				Config,
			) error {
				return nil
			},
			func(
				Config,
			) (
				sorPostgreSQLDatabaseObservation,
				sorPostgreSQLDatabaseState,
				error,
			) {
				return sorPostgreSQLDatabaseObservation{},
					sorPostgreSQLDatabaseUnknown,
					errors.New(
						"synthetic observer failure",
					)
			},
		)

	if err == nil {
		t.Fatal(
			"database observer failure was accepted",
		)
	}

	if !strings.Contains(
		err.Error(),
		"observe PostgreSQL database state",
	) {
		t.Fatalf(
			"error = %q",
			err,
		)
	}
}

func TestVerifySORPostgreSQLDatabaseRejectsNonOwnedMatch(
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
				err :=
					verifySORPostgreSQLDatabaseWith(
						Config{},
						func(
							Config,
						) error {
							return nil
						},
						func(
							Config,
						) (
							sorPostgreSQLDatabaseObservation,
							sorPostgreSQLDatabaseState,
							error,
						) {
							return sorPostgreSQLDatabaseObservation{},
								test.state,
								nil
						},
					)

				if err == nil {
					t.Fatalf(
						"state %s was accepted",
						test.state,
					)
				}

				if !strings.Contains(
					err.Error(),
					string(test.state),
				) {
					t.Fatalf(
						"error %q does not contain state %s",
						err,
						test.state,
					)
				}
			},
		)
	}
}
