// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"fmt"
	"os"
	"strings"
	"syscall"
)

const sorPostgreSQLSecurityFieldIndexQuery = `
SELECT
    target.oid IS NOT NULL,
    COALESCE(ns.nspname, ''),
    COALESCE(tbl.relname, ''),
    COALESCE(pg_catalog.pg_get_indexdef(idx.oid), ''),
    COALESCE(am.amname, ''),
    COALESCE(pg_catalog.pg_get_userbyid(tbl.relowner), ''),
    COALESCE(ind.indisunique, false),
    COALESCE(ind.indisprimary, false)
FROM (SELECT pg_catalog.to_regclass('fi.windows_security_event_field_name_idx') AS oid) AS target
LEFT JOIN pg_catalog.pg_class AS idx ON idx.oid = target.oid
LEFT JOIN pg_catalog.pg_index AS ind ON ind.indexrelid = idx.oid
LEFT JOIN pg_catalog.pg_class AS tbl ON tbl.oid = ind.indrelid
LEFT JOIN pg_catalog.pg_namespace AS ns ON ns.oid = tbl.relnamespace
LEFT JOIN pg_catalog.pg_am AS am ON am.oid = idx.relam;
`

const sorPostgreSQLSecurityFieldConstraintsQuery = `
SELECT
    count(*) FILTER (WHERE contype = 'p' AND conname = 'windows_security_event_field_pkey'),
    count(*) FILTER (WHERE contype = 'f' AND conname = 'windows_security_event_field_source_record_id_fkey'
        AND confrelid = 'fi.windows_security_event'::pg_catalog.regclass),
    count(*) FILTER (WHERE contype = 'c' AND conname = 'windows_security_event_field_field_ordinal_check'),
    count(*) FILTER (WHERE contype IN ('p', 'f', 'c'))
FROM pg_catalog.pg_constraint
WHERE conrelid = 'fi.windows_security_event_field'::pg_catalog.regclass;
`

const sorPostgreSQLSecurityFieldTableQuery = `
SELECT
    pg_catalog.pg_get_userbyid(cls.relowner),
    cls.relkind::text
FROM pg_catalog.pg_class AS cls
WHERE cls.oid = 'fi.windows_security_event_field'::pg_catalog.regclass;
`

type sorPostgreSQLDatabaseUpgradeQueryFunc func(string, string, int) ([]string, error)
type sorPostgreSQLDatabaseUpgradeExecFunc func(string, string, []byte) error

// UpgradeSORPostgreSQLDatabase is intentionally separate from initialization.
// Initialization requires stopped FI jails and replays all foundation SQL;
// this operation checks the existing foundation and applies only migration 0004.
func UpgradeSORPostgreSQLDatabase(config Config) error {
	// Exclude simultaneous upgrades launched on the same backend host.
	lock, err := os.OpenFile(
		"/var/run/fi-sor-database-upgrade.lock",
		os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW,
		0600,
	)
	if err != nil {
		return fmt.Errorf("open FI SOR upgrade lock: %w", err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fmt.Errorf("another FI SOR database upgrade may be active: %w", err)
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)

	policy, err := buildSORPostgreSQLDatabasePolicy(config)
	if err != nil {
		return fmt.Errorf("build FI SOR upgrade policy: %w", err)
	}

	assets := sorPostgreSQLDatabaseMigrationAssets()
	if err := validateSORPostgreSQLDatabaseMigrations(policy, assets); err != nil {
		return fmt.Errorf("validate FI SOR migration assets: %w", err)
	}
	if len(assets) != 4 || assets[3].Name != "0004_security_field_name_index.sql" ||
		!strings.Contains(assets[3].SQL, "DROP INDEX CONCURRENTLY fi.windows_security_event_field_name_idx;") {
		return fmt.Errorf("FI SOR index upgrade asset contract mismatch")
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
		return fmt.Errorf("FI SOR upgrade requires matching database, role, schema, and foundation authority")
	}

	return upgradeSORPostgreSQLSecurityFieldIndexWith(
		policy,
		assets[3],
		(sorPostgreSQLDatabaseQueryExecutor{}).Query,
		(sorPostgreSQLDatabaseSQLExecutor{}).ExecuteAsRole,
	)
}

func upgradeSORPostgreSQLSecurityFieldIndexWith(
	policy sorPostgreSQLDatabasePolicy,
	asset sorPostgreSQLDatabaseMigrationAsset,
	query sorPostgreSQLDatabaseUpgradeQueryFunc,
	execute sorPostgreSQLDatabaseUpgradeExecFunc,
) error {
	if query == nil || execute == nil {
		return fmt.Errorf("FI SOR upgrade requires query and SQL executors")
	}
	if policy.DatabaseName != "fi" || policy.OwnerRole.Name != "fi_owner" ||
		asset.Name != "0004_security_field_name_index.sql" ||
		asset.SHA256 != sorPostgreSQLDatabaseMigration0004SHA256 {
		return fmt.Errorf("FI SOR index upgrade policy mismatch")
	}

	if err := verifySORPostgreSQLSecurityFieldFoundation(query, policy.DatabaseName); err != nil {
		return fmt.Errorf("FI SOR Security field foundation: %w", err)
	}

	exists, err := observeSORPostgreSQLSecurityFieldIndex(query, policy.DatabaseName)
	if err != nil {
		return err
	}
	if !exists {
		// State-based recovery: an interrupted run after a successful DROP
		// may have removed the index before it could report completion.
		return nil
	}

	// CONCURRENTLY must be executed without BEGIN/COMMIT. The canonical
	// asset is executed through psql -f after a separate SET ROLE -c.
	if err := execute(policy.DatabaseName, policy.OwnerRole.Name, []byte(asset.SQL)); err != nil {
		return fmt.Errorf("drop FI SOR Security field-name index concurrently: %w", err)
	}

	exists, err = observeSORPostgreSQLSecurityFieldIndex(query, policy.DatabaseName)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("FI SOR Security field-name index still exists after migration 0004")
	}
	if err := verifySORPostgreSQLSecurityFieldFoundation(query, policy.DatabaseName); err != nil {
		return fmt.Errorf("verify FI SOR Security field foundation after migration: %w", err)
	}
	return nil
}

func verifySORPostgreSQLSecurityFieldFoundation(query sorPostgreSQLDatabaseUpgradeQueryFunc, database string) error {
	table, err := query(database, sorPostgreSQLSecurityFieldTableQuery, 2)
	if err != nil {
		return fmt.Errorf("inspect Security field table: %w", err)
	}
	if table[0] != "fi_owner" || table[1] != "r" {
		return fmt.Errorf("FI Security field table ownership or relation kind mismatch")
	}

	fields, err := query(database, sorPostgreSQLSecurityFieldConstraintsQuery, 4)
	if err != nil {
		return fmt.Errorf("inspect Security field constraints: %w", err)
	}
	for _, value := range fields {
		if value != "1" && value != "3" {
			return fmt.Errorf("unexpected FI Security field constraints: %q", fields)
		}
	}
	if fields[0] != "1" || fields[1] != "1" || fields[2] != "1" || fields[3] != "3" {
		return fmt.Errorf("FI Security field primary/foreign/check constraints are not exact: %q", fields)
	}
	return nil
}

func observeSORPostgreSQLSecurityFieldIndex(query sorPostgreSQLDatabaseUpgradeQueryFunc, database string) (bool, error) {
	fields, err := query(database, sorPostgreSQLSecurityFieldIndexQuery, 8)
	if err != nil {
		return false, fmt.Errorf("inspect Security field-name index: %w", err)
	}
	exists, err := parseSORPostgreSQLDatabasePSQLBool(fields[0])
	if err != nil {
		return false, err
	}
	if !exists {
		for _, v := range fields[1:] {
			if v != "" && v != "f" {
				return false, fmt.Errorf("FI Security field-name index absent but catalog fields are inconsistent")
			}
		}
		return false, nil
	}
	const expectedDef = "CREATE INDEX windows_security_event_field_name_idx ON fi.windows_security_event_field USING btree (name)"
	if fields[1] != "fi" || fields[2] != "windows_security_event_field" ||
		fields[3] != expectedDef || fields[4] != "btree" || fields[5] != "fi_owner" ||
		fields[6] != "f" || fields[7] != "f" {
		return false, fmt.Errorf("FI Security field-name index does not match canonical definition")
	}
	// An invalid index left by an interrupted concurrent operation retains
	// its definition and may be dropped on retry. Do not require indisvalid.
	return true, nil
}
