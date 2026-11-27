// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

type sorPostgreSQLDatabaseState string

const (
	sorPostgreSQLDatabaseAbsent sorPostgreSQLDatabaseState = "ABSENT"

	sorPostgreSQLDatabaseOwnedMatch sorPostgreSQLDatabaseState = "OWNED_MATCH"

	sorPostgreSQLDatabaseOwnedDrift sorPostgreSQLDatabaseState = "OWNED_DRIFT"

	sorPostgreSQLDatabaseForeignCollision sorPostgreSQLDatabaseState = "FOREIGN_COLLISION"

	sorPostgreSQLDatabaseUnknown sorPostgreSQLDatabaseState = "UNKNOWN"
)

type sorPostgreSQLDatabaseResourceState string

const (
	sorPostgreSQLDatabaseResourceAbsent sorPostgreSQLDatabaseResourceState = "ABSENT"

	sorPostgreSQLDatabaseResourceOwnedMatch sorPostgreSQLDatabaseResourceState = "OWNED_MATCH"

	sorPostgreSQLDatabaseResourceOwnedDrift sorPostgreSQLDatabaseResourceState = "OWNED_DRIFT"

	sorPostgreSQLDatabaseResourceForeignCollision sorPostgreSQLDatabaseResourceState = "FOREIGN_COLLISION"

	sorPostgreSQLDatabaseResourceUnknown sorPostgreSQLDatabaseResourceState = "UNKNOWN"
)

// sorPostgreSQLDatabaseObservation is a semantic snapshot produced by the
// future live PostgreSQL/database-policy probe.
//
// The state model deliberately does not know how PostgreSQL is queried.
// Inspection and mutation remain separate.
//
// Each resource must eventually prove:
//
//	OwnerRole
//	  fi_owner exists with the exact FI ownership marker and role attributes.
//
//	IngestRole
//	  fi_ingest exists with the exact FI ownership marker and restricted
//	  runtime role attributes.
//
//	Database
//	  database fi exists, is owned by fi_owner, and carries exact FI authority.
//
//	Schema
//	  schema fi exists, is owned by fi_owner, and carries exact FI authority.
//
//	RelationalFoundation
//	  the accepted 0001 -> 0002 -> 0003 relational foundation is exact.
//
//	Privileges
//	  fi_ingest has the exact permitted database/schema/table/sequence
//	  privileges and does not have prohibited mutation privileges.
//
//	Credential
//	  fi_ingest has the expected SCRAM credential and that credential matches
//	  the authoritative ingest passfile.
//
//	Passfile
//	  the host-controlled ingest postgres.pgpass is exact FI-owned state.
type sorPostgreSQLDatabaseObservation struct {
	OwnerRole            sorPostgreSQLDatabaseResourceState
	IngestRole           sorPostgreSQLDatabaseResourceState
	Database             sorPostgreSQLDatabaseResourceState
	Schema               sorPostgreSQLDatabaseResourceState
	RelationalFoundation sorPostgreSQLDatabaseResourceState
	Privileges           sorPostgreSQLDatabaseResourceState
	Credential           sorPostgreSQLDatabaseResourceState
	Passfile             sorPostgreSQLDatabaseResourceState
}

func classifySORPostgreSQLDatabase(
	observation sorPostgreSQLDatabaseObservation,
) sorPostgreSQLDatabaseState {
	states := []sorPostgreSQLDatabaseResourceState{
		observation.OwnerRole,
		observation.IngestRole,
		observation.Database,
		observation.Schema,
		observation.RelationalFoundation,
		observation.Privileges,
		observation.Credential,
		observation.Passfile,
	}

	for _, state := range states {
		if state ==
			sorPostgreSQLDatabaseResourceUnknown {
			return sorPostgreSQLDatabaseUnknown
		}
	}

	for _, state := range states {
		if state ==
			sorPostgreSQLDatabaseResourceForeignCollision {
			return sorPostgreSQLDatabaseForeignCollision
		}
	}

	allAbsent := true

	for _, state := range states {
		if state !=
			sorPostgreSQLDatabaseResourceAbsent {
			allAbsent = false
			break
		}
	}

	if allAbsent {
		return sorPostgreSQLDatabaseAbsent
	}

	allOwnedMatch := true

	for _, state := range states {
		if state !=
			sorPostgreSQLDatabaseResourceOwnedMatch {
			allOwnedMatch = false
			break
		}
	}

	if allOwnedMatch {
		return sorPostgreSQLDatabaseOwnedMatch
	}

	return sorPostgreSQLDatabaseOwnedDrift
}
