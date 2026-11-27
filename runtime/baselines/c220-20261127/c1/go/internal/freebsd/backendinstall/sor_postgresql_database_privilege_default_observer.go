// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import "fmt"

const (
	sorPostgreSQLDatabaseDefaultPrivilegeFieldCount = 16
)

func buildSORPostgreSQLDatabaseDefaultPrivilegeQuery(
	policy sorPostgreSQLDatabasePolicy,
) string {
	owner :=
		quoteSORPostgreSQLDatabaseSQLLiteral(
			policy.OwnerRole.Name,
		)

	ingest :=
		quoteSORPostgreSQLDatabaseSQLLiteral(
			policy.IngestRole.Name,
		)

	schema :=
		quoteSORPostgreSQLDatabaseSQLLiteral(
			policy.SchemaName,
		)

	return fmt.Sprintf(`
WITH
roles AS (
    SELECT
        (
            SELECT oid
            FROM pg_catalog.pg_roles
            WHERE rolname = %s
        ) AS owner_oid,
        (
            SELECT oid
            FROM pg_catalog.pg_roles
            WHERE rolname = %s
        ) AS ingest_oid
),
target_schema AS (
    SELECT oid
    FROM pg_catalog.pg_namespace
    WHERE nspname = %s
),
owner_defaults AS (
    SELECT
        default_acl.oid,
        default_acl.defaclnamespace,
        default_acl.defaclobjtype,
        default_acl.defaclacl
    FROM pg_catalog.pg_default_acl AS default_acl
    CROSS JOIN roles
    WHERE default_acl.defaclrole = roles.owner_oid
),
table_acl AS (
    SELECT
        acl.grantor,
        acl.grantee,
        acl.privilege_type,
        acl.is_grantable
    FROM owner_defaults AS default_acl
    CROSS JOIN target_schema
    CROSS JOIN LATERAL pg_catalog.aclexplode(
        default_acl.defaclacl
    ) AS acl
    WHERE default_acl.defaclnamespace = target_schema.oid
      AND default_acl.defaclobjtype = 'r'
),
sequence_acl AS (
    SELECT
        acl.grantor,
        acl.grantee,
        acl.privilege_type,
        acl.is_grantable
    FROM owner_defaults AS default_acl
    CROSS JOIN target_schema
    CROSS JOIN LATERAL pg_catalog.aclexplode(
        default_acl.defaclacl
    ) AS acl
    WHERE default_acl.defaclnamespace = target_schema.oid
      AND default_acl.defaclobjtype = 'S'
),
unexpected_default_acl AS (
    SELECT count(*)::integer AS count
    FROM (
        SELECT 1
        FROM owner_defaults AS default_acl
        CROSS JOIN target_schema
        WHERE NOT (
            default_acl.defaclnamespace = target_schema.oid
            AND default_acl.defaclobjtype IN ('r', 'S')
        )

        UNION ALL

        SELECT 1
        FROM table_acl AS acl
        CROSS JOIN roles
        WHERE NOT (
            acl.grantor = roles.owner_oid
            AND acl.grantee = roles.ingest_oid
            AND acl.privilege_type IN (
                'SELECT',
                'INSERT'
            )
            AND NOT acl.is_grantable
        )

        UNION ALL

        SELECT 1
        FROM sequence_acl AS acl
        CROSS JOIN roles
        WHERE NOT (
            acl.grantor = roles.owner_oid
            AND acl.grantee = roles.ingest_oid
            AND acl.privilege_type IN (
                'USAGE',
                'SELECT'
            )
            AND NOT acl.is_grantable
        )
    ) AS unexpected
)
SELECT
    EXISTS(
        SELECT 1
        FROM table_acl AS acl
        CROSS JOIN roles
        WHERE acl.grantor = roles.owner_oid
          AND acl.grantee = roles.ingest_oid
          AND acl.privilege_type = 'SELECT'
          AND NOT acl.is_grantable
    ),
    EXISTS(
        SELECT 1
        FROM table_acl AS acl
        CROSS JOIN roles
        WHERE acl.grantor = roles.owner_oid
          AND acl.grantee = roles.ingest_oid
          AND acl.privilege_type = 'INSERT'
          AND NOT acl.is_grantable
    ),
    EXISTS(
        SELECT 1
        FROM table_acl AS acl
        CROSS JOIN roles
        WHERE acl.grantor = roles.owner_oid
          AND acl.grantee = roles.ingest_oid
          AND acl.privilege_type = 'SELECT'
          AND acl.is_grantable
    ),
    EXISTS(
        SELECT 1
        FROM table_acl AS acl
        CROSS JOIN roles
        WHERE acl.grantor = roles.owner_oid
          AND acl.grantee = roles.ingest_oid
          AND acl.privilege_type = 'INSERT'
          AND acl.is_grantable
    ),
    EXISTS(
        SELECT 1
        FROM table_acl AS acl
        CROSS JOIN roles
        WHERE acl.grantee = roles.ingest_oid
          AND acl.privilege_type = 'UPDATE'
    ),
    EXISTS(
        SELECT 1
        FROM table_acl AS acl
        CROSS JOIN roles
        WHERE acl.grantee = roles.ingest_oid
          AND acl.privilege_type = 'DELETE'
    ),
    EXISTS(
        SELECT 1
        FROM table_acl AS acl
        CROSS JOIN roles
        WHERE acl.grantee = roles.ingest_oid
          AND acl.privilege_type = 'TRUNCATE'
    ),
    EXISTS(
        SELECT 1
        FROM table_acl AS acl
        CROSS JOIN roles
        WHERE acl.grantee = roles.ingest_oid
          AND acl.privilege_type = 'REFERENCES'
    ),
    EXISTS(
        SELECT 1
        FROM table_acl AS acl
        CROSS JOIN roles
        WHERE acl.grantee = roles.ingest_oid
          AND acl.privilege_type = 'TRIGGER'
    ),
    EXISTS(
        SELECT 1
        FROM table_acl AS acl
        CROSS JOIN roles
        WHERE acl.grantee = roles.ingest_oid
          AND acl.privilege_type = 'MAINTAIN'
    ),
    EXISTS(
        SELECT 1
        FROM sequence_acl AS acl
        CROSS JOIN roles
        WHERE acl.grantor = roles.owner_oid
          AND acl.grantee = roles.ingest_oid
          AND acl.privilege_type = 'USAGE'
          AND NOT acl.is_grantable
    ),
    EXISTS(
        SELECT 1
        FROM sequence_acl AS acl
        CROSS JOIN roles
        WHERE acl.grantor = roles.owner_oid
          AND acl.grantee = roles.ingest_oid
          AND acl.privilege_type = 'SELECT'
          AND NOT acl.is_grantable
    ),
    EXISTS(
        SELECT 1
        FROM sequence_acl AS acl
        CROSS JOIN roles
        WHERE acl.grantor = roles.owner_oid
          AND acl.grantee = roles.ingest_oid
          AND acl.privilege_type = 'USAGE'
          AND acl.is_grantable
    ),
    EXISTS(
        SELECT 1
        FROM sequence_acl AS acl
        CROSS JOIN roles
        WHERE acl.grantor = roles.owner_oid
          AND acl.grantee = roles.ingest_oid
          AND acl.privilege_type = 'SELECT'
          AND acl.is_grantable
    ),
    EXISTS(
        SELECT 1
        FROM sequence_acl AS acl
        CROSS JOIN roles
        WHERE acl.grantee = roles.ingest_oid
          AND acl.privilege_type = 'UPDATE'
    ),
    (
        SELECT count
        FROM unexpected_default_acl
    )
FROM roles
CROSS JOIN target_schema;
`,
		owner,
		ingest,
		schema,
	)
}

func observeSORPostgreSQLDatabaseDefaultPrivileges(
	query func(
		string,
		string,
		int,
	) ([]string, error),
	policy sorPostgreSQLDatabasePolicy,
) (sorPostgreSQLDatabasePrivilegeFacts, error) {
	fields, err :=
		query(
			policy.DatabaseName,
			buildSORPostgreSQLDatabaseDefaultPrivilegeQuery(
				policy,
			),
			sorPostgreSQLDatabaseDefaultPrivilegeFieldCount,
		)
	if err != nil {
		return sorPostgreSQLDatabasePrivilegeFacts{},
			err
	}

	return parseSORPostgreSQLDatabaseDefaultPrivilegeFacts(
		fields,
	)
}

func parseSORPostgreSQLDatabaseDefaultPrivilegeFacts(
	fields []string,
) (sorPostgreSQLDatabasePrivilegeFacts, error) {
	if len(fields) !=
		sorPostgreSQLDatabaseDefaultPrivilegeFieldCount {
		return sorPostgreSQLDatabasePrivilegeFacts{},
			fmt.Errorf(
				"PostgreSQL default privilege field count = %d, want %d",
				len(fields),
				sorPostgreSQLDatabaseDefaultPrivilegeFieldCount,
			)
	}

	boolField :=
		func(
			index int,
			label string,
		) (bool, error) {
			value, err :=
				parseSORPostgreSQLDatabasePSQLBool(
					fields[index],
				)
			if err != nil {
				return false,
					fmt.Errorf(
						"parse PostgreSQL %s: %w",
						label,
						err,
					)
			}

			return value, nil
		}

	facts :=
		sorPostgreSQLDatabasePrivilegeFacts{}

	var err error

	if facts.DefaultTableSelect, err =
		boolField(0, "default table SELECT privilege"); err != nil {
		return sorPostgreSQLDatabasePrivilegeFacts{}, err
	}

	if facts.DefaultTableInsert, err =
		boolField(1, "default table INSERT privilege"); err != nil {
		return sorPostgreSQLDatabasePrivilegeFacts{}, err
	}

	if facts.DefaultTableSelectGrantOption, err =
		boolField(2, "default table SELECT grant option"); err != nil {
		return sorPostgreSQLDatabasePrivilegeFacts{}, err
	}

	if facts.DefaultTableInsertGrantOption, err =
		boolField(3, "default table INSERT grant option"); err != nil {
		return sorPostgreSQLDatabasePrivilegeFacts{}, err
	}

	if facts.DefaultTableUpdate, err =
		boolField(4, "default table UPDATE privilege"); err != nil {
		return sorPostgreSQLDatabasePrivilegeFacts{}, err
	}

	if facts.DefaultTableDelete, err =
		boolField(5, "default table DELETE privilege"); err != nil {
		return sorPostgreSQLDatabasePrivilegeFacts{}, err
	}

	if facts.DefaultTableTruncate, err =
		boolField(6, "default table TRUNCATE privilege"); err != nil {
		return sorPostgreSQLDatabasePrivilegeFacts{}, err
	}

	if facts.DefaultTableReferences, err =
		boolField(7, "default table REFERENCES privilege"); err != nil {
		return sorPostgreSQLDatabasePrivilegeFacts{}, err
	}

	if facts.DefaultTableTrigger, err =
		boolField(8, "default table TRIGGER privilege"); err != nil {
		return sorPostgreSQLDatabasePrivilegeFacts{}, err
	}

	if facts.DefaultTableMaintain, err =
		boolField(9, "default table MAINTAIN privilege"); err != nil {
		return sorPostgreSQLDatabasePrivilegeFacts{}, err
	}

	if facts.DefaultSequenceUsage, err =
		boolField(10, "default sequence USAGE privilege"); err != nil {
		return sorPostgreSQLDatabasePrivilegeFacts{}, err
	}

	if facts.DefaultSequenceSelect, err =
		boolField(11, "default sequence SELECT privilege"); err != nil {
		return sorPostgreSQLDatabasePrivilegeFacts{}, err
	}

	if facts.DefaultSequenceUsageGrantOption, err =
		boolField(12, "default sequence USAGE grant option"); err != nil {
		return sorPostgreSQLDatabasePrivilegeFacts{}, err
	}

	if facts.DefaultSequenceSelectGrantOption, err =
		boolField(13, "default sequence SELECT grant option"); err != nil {
		return sorPostgreSQLDatabasePrivilegeFacts{}, err
	}

	if facts.DefaultSequenceUpdate, err =
		boolField(14, "default sequence UPDATE privilege"); err != nil {
		return sorPostgreSQLDatabasePrivilegeFacts{}, err
	}

	count, err :=
		parseSORPostgreSQLDatabasePSQLInt(
			fields[15],
		)
	if err != nil {
		return sorPostgreSQLDatabasePrivilegeFacts{},
			fmt.Errorf(
				"parse PostgreSQL unexpected default ACL count: %w",
				err,
			)
	}

	if count < 0 {
		return sorPostgreSQLDatabasePrivilegeFacts{},
			fmt.Errorf(
				"PostgreSQL unexpected default ACL count is negative",
			)
	}

	facts.UnexpectedDefaultACLGrantCount =
		count

	return facts, nil
}
