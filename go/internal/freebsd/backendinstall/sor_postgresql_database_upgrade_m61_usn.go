// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
)

// The catalog check runs before any schema write. It distinguishes pristine
// legacy schema, canonical M6.1 schema, and drifted/partial installations.
// pg_get_constraintdef strings are the exact PostgreSQL 18.6 catalog output
// from the successfully upgraded FI development database on 2026-10-23.
// The definition count checks SQL semantics, not just constraint names.
const sorM61USNCatalogQuery = `
SELECT
 (SELECT count(*) FROM information_schema.columns
  WHERE table_schema='fi' AND table_name='usn_read_boundary'
    AND column_name IN ('source_batch_sha256','correlation_sha256','root_ntfs_object_id')),
 (SELECT count(*) FROM information_schema.columns
  WHERE table_schema='fi' AND table_name='usn_read_boundary'
    AND is_nullable='YES' AND column_default IS NULL
    AND ((column_name IN ('source_batch_sha256','correlation_sha256') AND data_type='bytea')
      OR (column_name='root_ntfs_object_id' AND data_type='bigint'))),
 (SELECT count(*) FROM information_schema.columns
  WHERE table_schema='fi' AND table_name='usn_object_observation'
    AND column_name='source_batch_sha256'),
 (SELECT count(*) FROM information_schema.columns
  WHERE table_schema='fi' AND table_name='usn_object_observation'
    AND column_name='source_batch_sha256' AND data_type='bytea'
    AND is_nullable='YES' AND column_default IS NULL),
 (SELECT count(*) FROM pg_catalog.pg_constraint AS c
  WHERE (c.conrelid='fi.usn_read_boundary'::regclass
    AND c.conname IN ('usn_capture_root_fk','usn_capture_contract_ck'))
    OR (c.conrelid='fi.usn_object_observation'::regclass
      AND c.conname='usn_object_capture_digest_ck')),
 (SELECT count(*) FROM pg_catalog.pg_constraint AS c
  WHERE NOT c.condeferrable AND NOT c.condeferred AND
   ((c.conrelid='fi.usn_read_boundary'::regclass
     AND c.conname='usn_capture_root_fk' AND c.contype='f'
     AND c.confrelid='fi.ntfs_object'::regclass
     AND pg_catalog.pg_get_constraintdef(c.oid,false)=$fi_m61$FOREIGN KEY (root_ntfs_object_id) REFERENCES fi.ntfs_object(ntfs_object_id)$fi_m61$)
    OR (c.conrelid='fi.usn_read_boundary'::regclass
     AND c.conname='usn_capture_contract_ck' AND c.contype='c'
     AND pg_catalog.pg_get_constraintdef(c.oid,false)=$fi_m61$CHECK ((((source_batch_sha256 IS NULL) AND (correlation_sha256 IS NULL) AND (root_ntfs_object_id IS NULL) AND (usn_read_operation_id IS NOT NULL) AND (usn_read_operation_id <> ''::text)) OR ((source_batch_sha256 IS NOT NULL) AND (octet_length(source_batch_sha256) = 32) AND (correlation_sha256 IS NOT NULL) AND (octet_length(correlation_sha256) = 32) AND (root_ntfs_object_id IS NOT NULL) AND (usn_read_operation_id IS NULL))))$fi_m61$)
    OR (c.conrelid='fi.usn_object_observation'::regclass
     AND c.conname='usn_object_capture_digest_ck' AND c.contype='c'
     AND pg_catalog.pg_get_constraintdef(c.oid,false)=$fi_m61$CHECK (((source_batch_sha256 IS NULL) OR (octet_length(source_batch_sha256) = 32)))$fi_m61$))),
 (SELECT count(*) FROM pg_catalog.pg_constraint AS c
  WHERE c.convalidated AND
   ((c.conrelid='fi.usn_read_boundary'::regclass
    AND c.conname IN ('usn_capture_root_fk','usn_capture_contract_ck'))
     OR (c.conrelid='fi.usn_object_observation'::regclass
      AND c.conname='usn_object_capture_digest_ck'))),
 (SELECT pg_catalog.pg_get_userbyid(relowner) FROM pg_catalog.pg_class
  WHERE oid='fi.usn_read_boundary'::regclass),
 (SELECT pg_catalog.pg_get_userbyid(relowner) FROM pg_catalog.pg_class
  WHERE oid='fi.usn_object_observation'::regclass),
 (SELECT is_nullable FROM information_schema.columns
  WHERE table_schema='fi' AND table_name='usn_read_boundary'
    AND column_name='usn_read_operation_id');
`

const sorM61USNValidateSQL = `
SET lock_timeout = '3s';
ALTER TABLE fi.usn_read_boundary VALIDATE CONSTRAINT usn_capture_root_fk;
ALTER TABLE fi.usn_read_boundary VALIDATE CONSTRAINT usn_capture_contract_ck;
ALTER TABLE fi.usn_object_observation VALIDATE CONSTRAINT usn_object_capture_digest_ck;
`

type sorM61USNCatalogState struct {
	boundaryColumns int
	boundaryTyped   int
	objectColumns   int
	objectTyped     int
	constraints     int
	definitions     int
	validated       int
	boundaryOwner   string
	objectOwner     string
	operationNull   string
}

func (state sorM61USNCatalogState) legacy() bool {
	return state.boundaryColumns == 0 && state.boundaryTyped == 0 &&
		state.objectColumns == 0 && state.objectTyped == 0 &&
		state.constraints == 0 && state.definitions == 0 &&
		state.validated == 0 &&
		state.boundaryOwner == "fi_owner" && state.objectOwner == "fi_owner" &&
		state.operationNull == "NO"
}

func (state sorM61USNCatalogState) installed() bool {
	return state.boundaryColumns == 3 && state.boundaryTyped == 3 &&
		state.objectColumns == 1 && state.objectTyped == 1 &&
		state.constraints == 3 && state.definitions == 3 &&
		state.validated >= 0 &&
		state.validated <= 3 && state.boundaryOwner == "fi_owner" &&
		state.objectOwner == "fi_owner" && state.operationNull == "YES"
}

func inspectSORM61USNCatalog(query sorPostgreSQLDatabaseUpgradeQueryFunc) (sorM61USNCatalogState, error) {
	if query == nil {
		return sorM61USNCatalogState{}, fmt.Errorf("FI M6.1 catalog query is required")
	}
	fields, err := query("fi", sorM61USNCatalogQuery, 10)
	if err != nil {
		return sorM61USNCatalogState{}, fmt.Errorf("inspect FI M6.1 USN catalog: %w", err)
	}
	if len(fields) != 10 {
		return sorM61USNCatalogState{}, fmt.Errorf("FI M6.1 catalog returned %d fields, expected 10", len(fields))
	}
	var numbers [7]int
	for i := range numbers {
		numbers[i], err = strconv.Atoi(fields[i])
		if err != nil || numbers[i] < 0 {
			return sorM61USNCatalogState{}, fmt.Errorf("invalid FI M6.1 catalog count %d: %q", i, fields[i])
		}
	}
	return sorM61USNCatalogState{
		boundaryColumns: numbers[0], boundaryTyped: numbers[1],
		objectColumns: numbers[2], objectTyped: numbers[3],
		constraints: numbers[4], definitions: numbers[5], validated: numbers[6],
		boundaryOwner: fields[7], objectOwner: fields[8], operationNull: fields[9],
	}, nil
}

// UpgradeM61USNCaptureBinding is separate from initialization and from the
// pre-existing 0004 security-field-index upgrade. No old migration is replayed.
// A shared host advisory lock serializes all FI SOR upgrade entry points.
func UpgradeM61USNCaptureBinding(config Config) error {
	lock, err := os.OpenFile("/var/run/fi-sor-database-upgrade.lock",
		os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("open FI SOR M6.1 upgrade lock: %w", err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fmt.Errorf("another FI SOR upgrade is active: %w", err)
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)

	policy, err := buildSORPostgreSQLDatabasePolicy(config)
	if err != nil {
		return err
	}
	assets := sorPostgreSQLDatabaseMigrationAssets()
	if err := validateSORPostgreSQLDatabaseMigrations(policy, assets); err != nil {
		return err
	}
	if len(assets) != 5 || assets[4].Name != "0005_usn_capture_binding.sql" ||
		assets[4].SHA256 != sorPostgreSQLDatabaseMigration0005SHA256 {
		return fmt.Errorf("FI M6.1 migration asset contract mismatch")
	}

	facts, err := (sorPostgreSQLDatabaseCatalogObserver{}).Observe(policy)
	if err != nil {
		return fmt.Errorf("inspect existing FI SOR catalog: %w", err)
	}
	if classifySORPostgreSQLDatabaseCatalogRole(policy.OwnerRole, facts.OwnerRole) != sorPostgreSQLDatabaseResourceOwnedMatch ||
		classifySORPostgreSQLDatabaseCatalogRole(policy.IngestRole, facts.IngestRole) != sorPostgreSQLDatabaseResourceOwnedMatch ||
		classifySORPostgreSQLDatabaseCatalogDatabase(policy, facts.Database) != sorPostgreSQLDatabaseResourceOwnedMatch ||
		classifySORPostgreSQLDatabaseCatalogSchema(policy, facts.Schema) != sorPostgreSQLDatabaseResourceOwnedMatch ||
		classifySORPostgreSQLDatabaseCatalogFoundation(policy, facts.Foundation) != sorPostgreSQLDatabaseResourceOwnedMatch {
		return fmt.Errorf("FI M6.1 upgrade requires exact existing FI database authority")
	}

	return upgradeSORM61USNWith(assets[4],
		(sorPostgreSQLDatabaseQueryExecutor{}).Query,
		(sorPostgreSQLDatabaseSQLExecutor{}).ExecuteAsRole)
}

// upgradeSORM61USNWith supports retries after a successful short metadata
// phase and an interrupted later validation. It refuses partial or foreign
// column definitions instead of guessing or overwriting existing objects.
func upgradeSORM61USNWith(asset sorPostgreSQLDatabaseMigrationAsset,
	query sorPostgreSQLDatabaseUpgradeQueryFunc,
	execute sorPostgreSQLDatabaseUpgradeExecFunc) error {
	if query == nil || execute == nil || asset.Name != "0005_usn_capture_binding.sql" ||
		asset.SHA256 != sorPostgreSQLDatabaseMigration0005SHA256 ||
		asset.SQL != sorPostgreSQLDatabaseMigration0005Asset {
		return fmt.Errorf("FI M6.1 upgrade input/asset mismatch")
	}

	before, err := inspectSORM61USNCatalog(query)
	if err != nil {
		return err
	}
	switch {
	case before.legacy():
		if err := execute("fi", "fi_owner", []byte(asset.SQL)); err != nil {
			return fmt.Errorf("apply M6.1 additive USN migration: %w", err)
		}
	case before.installed():
		if before.validated == 3 {
			return nil
		}
		if err := execute("fi", "fi_owner", []byte(sorM61USNValidateSQL)); err != nil {
			return fmt.Errorf("resume FI M6.1 USN validation: %w", err)
		}
	default:
		return fmt.Errorf("FI M6.1 schema is partially installed or has drift; refusing migration")
	}

	after, err := inspectSORM61USNCatalog(query)
	if err != nil {
		return err
	}
	if !after.installed() || after.validated != 3 {
		return fmt.Errorf("FI M6.1 schema not fully validated after upgrade")
	}
	return nil
}
