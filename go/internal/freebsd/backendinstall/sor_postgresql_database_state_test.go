// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import "testing"

func TestClassifySORPostgreSQLDatabaseAbsent(
	t *testing.T,
) {
	observation :=
		sorPostgreSQLDatabaseObservation{
			OwnerRole:            sorPostgreSQLDatabaseResourceAbsent,
			IngestRole:           sorPostgreSQLDatabaseResourceAbsent,
			Database:             sorPostgreSQLDatabaseResourceAbsent,
			Schema:               sorPostgreSQLDatabaseResourceAbsent,
			RelationalFoundation: sorPostgreSQLDatabaseResourceAbsent,
			Privileges:           sorPostgreSQLDatabaseResourceAbsent,
			Credential:           sorPostgreSQLDatabaseResourceAbsent,
			Passfile:             sorPostgreSQLDatabaseResourceAbsent,
		}

	assertSORPostgreSQLDatabaseState(
		t,
		observation,
		sorPostgreSQLDatabaseAbsent,
	)
}

func TestClassifySORPostgreSQLDatabaseOwnedMatch(
	t *testing.T,
) {
	observation :=
		testSORPostgreSQLDatabaseOwnedMatchObservation()

	assertSORPostgreSQLDatabaseState(
		t,
		observation,
		sorPostgreSQLDatabaseOwnedMatch,
	)
}

func TestClassifySORPostgreSQLDatabasePartialIsOwnedDrift(
	t *testing.T,
) {
	observation :=
		testSORPostgreSQLDatabaseOwnedMatchObservation()

	observation.Credential =
		sorPostgreSQLDatabaseResourceAbsent

	assertSORPostgreSQLDatabaseState(
		t,
		observation,
		sorPostgreSQLDatabaseOwnedDrift,
	)
}

func TestClassifySORPostgreSQLDatabaseExplicitDrift(
	t *testing.T,
) {
	observation :=
		testSORPostgreSQLDatabaseOwnedMatchObservation()

	observation.Privileges =
		sorPostgreSQLDatabaseResourceOwnedDrift

	assertSORPostgreSQLDatabaseState(
		t,
		observation,
		sorPostgreSQLDatabaseOwnedDrift,
	)
}

func TestClassifySORPostgreSQLDatabaseForeignCollisionPrecedence(
	t *testing.T,
) {
	observation :=
		testSORPostgreSQLDatabaseOwnedMatchObservation()

	observation.Database =
		sorPostgreSQLDatabaseResourceForeignCollision

	observation.Privileges =
		sorPostgreSQLDatabaseResourceOwnedDrift

	assertSORPostgreSQLDatabaseState(
		t,
		observation,
		sorPostgreSQLDatabaseForeignCollision,
	)
}

func TestClassifySORPostgreSQLDatabaseUnknownPrecedence(
	t *testing.T,
) {
	observation :=
		testSORPostgreSQLDatabaseOwnedMatchObservation()

	observation.Database =
		sorPostgreSQLDatabaseResourceForeignCollision

	observation.Schema =
		sorPostgreSQLDatabaseResourceUnknown

	assertSORPostgreSQLDatabaseState(
		t,
		observation,
		sorPostgreSQLDatabaseUnknown,
	)
}

func TestClassifySORPostgreSQLDatabaseMixedAbsentAndOwnedIsDrift(
	t *testing.T,
) {
	observation :=
		sorPostgreSQLDatabaseObservation{
			OwnerRole:            sorPostgreSQLDatabaseResourceOwnedMatch,
			IngestRole:           sorPostgreSQLDatabaseResourceAbsent,
			Database:             sorPostgreSQLDatabaseResourceAbsent,
			Schema:               sorPostgreSQLDatabaseResourceAbsent,
			RelationalFoundation: sorPostgreSQLDatabaseResourceAbsent,
			Privileges:           sorPostgreSQLDatabaseResourceAbsent,
			Credential:           sorPostgreSQLDatabaseResourceAbsent,
			Passfile:             sorPostgreSQLDatabaseResourceAbsent,
		}

	assertSORPostgreSQLDatabaseState(
		t,
		observation,
		sorPostgreSQLDatabaseOwnedDrift,
	)
}

func TestClassifySORPostgreSQLDatabaseUnknownResourceValueFailsClosed(
	t *testing.T,
) {
	observation :=
		testSORPostgreSQLDatabaseOwnedMatchObservation()

	observation.Schema =
		sorPostgreSQLDatabaseResourceState(
			"INVALID",
		)

	assertSORPostgreSQLDatabaseState(
		t,
		observation,
		sorPostgreSQLDatabaseOwnedDrift,
	)
}

func testSORPostgreSQLDatabaseOwnedMatchObservation() sorPostgreSQLDatabaseObservation {
	return sorPostgreSQLDatabaseObservation{
		OwnerRole:            sorPostgreSQLDatabaseResourceOwnedMatch,
		IngestRole:           sorPostgreSQLDatabaseResourceOwnedMatch,
		Database:             sorPostgreSQLDatabaseResourceOwnedMatch,
		Schema:               sorPostgreSQLDatabaseResourceOwnedMatch,
		RelationalFoundation: sorPostgreSQLDatabaseResourceOwnedMatch,
		Privileges:           sorPostgreSQLDatabaseResourceOwnedMatch,
		Credential:           sorPostgreSQLDatabaseResourceOwnedMatch,
		Passfile:             sorPostgreSQLDatabaseResourceOwnedMatch,
	}
}

func assertSORPostgreSQLDatabaseState(
	t *testing.T,
	observation sorPostgreSQLDatabaseObservation,
	expected sorPostgreSQLDatabaseState,
) {
	t.Helper()

	actual :=
		classifySORPostgreSQLDatabase(
			observation,
		)

	if actual != expected {
		t.Fatalf(
			"state = %s, want %s",
			actual,
			expected,
		)
	}
}
