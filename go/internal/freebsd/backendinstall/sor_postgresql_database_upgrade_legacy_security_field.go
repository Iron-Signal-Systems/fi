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

// The legacy upgrade deliberately does not create or modify FI authority
// comments. Its bounded purpose is to remove migration 0004's index from a
// fully populated, FI-owned foundation predating those authority comments.
// A marked or partially marked installation is never eligible.
const sorPostgreSQLLegacySecurityFieldAuthorityQuery = `
SELECT
    (SELECT pg_catalog.shobj_description(oid, 'pg_authid') IS NULL
       FROM pg_catalog.pg_authid WHERE rolname = 'fi_owner'),
    (SELECT pg_catalog.shobj_description(oid, 'pg_authid') IS NULL
       FROM pg_catalog.pg_authid WHERE rolname = 'fi_ingest'),
    (SELECT pg_catalog.shobj_description(oid, 'pg_database') IS NULL
       FROM pg_catalog.pg_database WHERE datname = 'fi'),
    (SELECT pg_catalog.obj_description(oid, 'pg_namespace') IS NULL
       FROM pg_catalog.pg_namespace WHERE nspname = 'fi'),
    (SELECT count(*)
       FROM pg_catalog.pg_class AS c
       JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
      WHERE n.nspname = 'fi' AND c.relkind IN ('r', 'p')),
    (SELECT count(*)
       FROM pg_catalog.pg_class AS c
       JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
      WHERE n.nspname = 'fi' AND c.relkind IN ('r', 'p')
        AND pg_catalog.pg_get_userbyid(c.relowner) = 'fi_owner');
`

// UpgradeLegacySORPostgreSQLDatabase is an explicitly selected, legacy-only
// upgrade entry point. It does not call initialization or replay 0001-0003.
// The advisory host lock is shared with the strict upgrade command.
func UpgradeLegacySORPostgreSQLDatabase(config Config) error {
	lock, err := os.OpenFile(
		"/var/run/fi-sor-database-upgrade.lock",
		os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW,
		0600,
	)
	if err != nil {
		return fmt.Errorf("open FI legacy SOR upgrade lock: %w", err)
	}
	defer lock.Close()

	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fmt.Errorf("another FI SOR upgrade may be active: %w", err)
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)

	policy, err := buildSORPostgreSQLDatabasePolicy(config)
	if err != nil {
		return fmt.Errorf("build FI legacy SOR policy: %w", err)
	}

	assets := sorPostgreSQLDatabaseMigrationAssets()
	if err := validateSORPostgreSQLDatabaseMigrations(policy, assets); err != nil {
		return fmt.Errorf("validate FI legacy SOR migration assets: %w", err)
	}
	if len(assets) != 5 ||
		assets[3].Name != "0004_security_field_name_index.sql" ||
		assets[3].SHA256 != sorPostgreSQLDatabaseMigration0004SHA256 ||
		!strings.Contains(assets[3].SQL,
			"DROP INDEX CONCURRENTLY fi.windows_security_event_field_name_idx;") {
		return fmt.Errorf("FI legacy SOR migration 0004 contract mismatch")
	}

	facts, err := (sorPostgreSQLDatabaseCatalogObserver{}).Observe(policy)
	if err != nil {
		return fmt.Errorf("inspect legacy FI SOR catalog: %w", err)
	}

	query := (sorPostgreSQLDatabaseQueryExecutor{}).Query
	if err := verifyLegacySORPostgreSQLSecurityFieldOwnership(policy, facts, query); err != nil {
		return fmt.Errorf("FI legacy SOR ownership preflight: %w", err)
	}

	return upgradeSORPostgreSQLSecurityFieldIndexWith(
		policy,
		assets[3],
		query,
		(sorPostgreSQLDatabaseSQLExecutor{}).ExecuteAsRole,
	)
}

func verifyLegacySORPostgreSQLSecurityFieldOwnership(
	policy sorPostgreSQLDatabasePolicy,
	facts sorPostgreSQLDatabaseCatalogFacts,
	query sorPostgreSQLDatabaseUpgradeQueryFunc,
) error {
	if query == nil || policy.DatabaseName != "fi" ||
		policy.OwnerRole.Name != "fi_owner" ||
		policy.IngestRole.Name != "fi_ingest" ||
		policy.SchemaName != "fi" {
		return fmt.Errorf("FI legacy SOR policy or query is missing")
	}

	// The existing foundation's bootstrap fingerprints are retained in policy,
	// but legacy installations must have no managed comments at all.
	if !matchLegacySORPostgreSQLRole(policy.OwnerRole, facts.OwnerRole) ||
		!matchLegacySORPostgreSQLRole(policy.IngestRole, facts.IngestRole) {
		return fmt.Errorf("FI legacy SOR roles have unexpected properties")
	}

	db := facts.Database
	if !db.Exists || db.Comment != "" || db.Owner != policy.DatabaseOwner ||
		db.Encoding != policy.DatabaseEncoding ||
		db.Collate != policy.DatabaseCollate || db.CType != policy.DatabaseCType {
		return fmt.Errorf("FI legacy SOR database ownership or definition differs")
	}

	schema := facts.Schema
	if !schema.Exists || schema.Comment != "" || schema.Owner != policy.SchemaOwner {
		return fmt.Errorf("FI legacy SOR schema ownership differs")
	}

	foundation := facts.Foundation
	if !foundation.Exists || foundation.SchemaComment != "" ||
		foundation.TableCount != policy.ExpectedRelationalTableCount ||
		foundation.BadTypedColumns != 0 || foundation.MissingCoreTables != 0 {
		return fmt.Errorf("FI legacy SOR relational foundation does not match")
	}

	fields, err := query(policy.DatabaseName, sorPostgreSQLLegacySecurityFieldAuthorityQuery, 6)
	if err != nil {
		return fmt.Errorf("inspect legacy FI SOR authority and table owners: %w", err)
	}
	for i := 0; i < 4; i++ {
		if fields[i] != "t" {
			return fmt.Errorf("FI legacy SOR authority comment %d is not NULL", i)
		}
	}
	expectedCount := fmt.Sprint(policy.ExpectedRelationalTableCount)
	if fields[4] != expectedCount || fields[5] != expectedCount {
		return fmt.Errorf("FI legacy SOR tables are not exclusively owned by fi_owner: total=%q owner=%q expected=%s",
			fields[4], fields[5], expectedCount)
	}
	return nil
}

func matchLegacySORPostgreSQLRole(
	expected sorPostgreSQLDatabaseRolePolicy,
	actual sorPostgreSQLDatabaseCatalogRoleFacts,
) bool {
	return actual.Exists && actual.Comment == "" &&
		actual.BypassRLS == expected.BypassRLS &&
		actual.CanLogin == expected.CanLogin &&
		actual.ConnectionLimit == expected.ConnectionLimit &&
		actual.CreateDB == expected.CreateDB &&
		actual.CreateRole == expected.CreateRole &&
		actual.GrantedToCount == 0 &&
		actual.Inherit == expected.Inherit &&
		actual.MemberOfCount == 0 &&
		actual.PasswordPresent == expected.PasswordRequired &&
		actual.Replication == expected.Replication &&
		actual.Superuser == expected.Superuser &&
		actual.ValidUntilInfinity == expected.ValidUntilInfinity
}
