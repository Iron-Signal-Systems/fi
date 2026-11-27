// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import "fmt"

const (
	sorPostgreSQLDatabaseExplicitPrivilegeFieldCount = 33
)

func buildSORPostgreSQLDatabaseExplicitPrivilegeQuery(
	policy sorPostgreSQLDatabasePolicy,
) string {
	database :=
		quoteSORPostgreSQLDatabaseSQLLiteral(
			policy.DatabaseName,
		)

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
target_database AS (
    SELECT
        oid,
        datacl,
        datdba
    FROM pg_catalog.pg_database
    WHERE datname = %s
),
target_schema AS (
    SELECT
        oid,
        nspacl,
        nspowner
    FROM pg_catalog.pg_namespace
    WHERE nspname = %s
),
default_public_schema AS (
    SELECT
        oid,
        nspacl,
        nspowner
    FROM pg_catalog.pg_namespace
    WHERE nspname = 'public'
),
target_tables AS (
    SELECT
        class.oid,
        class.relacl,
        class.relowner
    FROM pg_catalog.pg_class AS class
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = class.relnamespace
    WHERE namespace.nspname = %s
      AND class.relkind IN ('r', 'p')
),
target_sequences AS (
    SELECT
        class.oid,
        class.relacl,
        class.relowner
    FROM pg_catalog.pg_class AS class
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = class.relnamespace
    WHERE namespace.nspname = %s
      AND class.relkind = 'S'
),
database_unexpected AS (
    SELECT count(*)::integer AS count
    FROM target_database AS database
    CROSS JOIN roles
    CROSS JOIN LATERAL pg_catalog.aclexplode(
        database.datacl
    ) AS acl
    WHERE acl.grantee <> 0
      AND acl.grantee <> database.datdba
      AND acl.grantee IS DISTINCT FROM roles.ingest_oid
),
schema_unexpected AS (
    SELECT count(*)::integer AS count
    FROM target_schema AS schema
    CROSS JOIN roles
    CROSS JOIN LATERAL pg_catalog.aclexplode(
        schema.nspacl
    ) AS acl
    WHERE acl.grantee <> 0
      AND acl.grantee <> schema.nspowner
      AND acl.grantee IS DISTINCT FROM roles.ingest_oid
),
public_schema_unexpected AS (
    SELECT count(*)::integer AS count
    FROM default_public_schema AS schema
    CROSS JOIN LATERAL pg_catalog.aclexplode(
        schema.nspacl
    ) AS acl
    WHERE acl.privilege_type = 'CREATE'
      AND acl.grantee <> schema.nspowner
),
table_unexpected AS (
    SELECT count(*)::integer AS count
    FROM target_tables AS table_object
    CROSS JOIN roles
    CROSS JOIN LATERAL pg_catalog.aclexplode(
        table_object.relacl
    ) AS acl
    WHERE acl.grantee <> table_object.relowner
      AND NOT (
          acl.grantee = roles.ingest_oid
          AND acl.privilege_type IN (
              'SELECT',
              'INSERT'
          )
          AND NOT acl.is_grantable
      )
),
column_unexpected AS (
    SELECT count(*)::integer AS count
    FROM target_tables AS table_object
    JOIN pg_catalog.pg_attribute AS attribute
      ON attribute.attrelid = table_object.oid
    CROSS JOIN LATERAL pg_catalog.aclexplode(
        attribute.attacl
    ) AS acl
    WHERE attribute.attnum > 0
      AND NOT attribute.attisdropped
      AND acl.grantee <> table_object.relowner
),
sequence_unexpected AS (
    SELECT count(*)::integer AS count
    FROM target_sequences AS sequence_object
    CROSS JOIN roles
    CROSS JOIN LATERAL pg_catalog.aclexplode(
        sequence_object.relacl
    ) AS acl
    WHERE acl.grantee <> sequence_object.relowner
      AND NOT (
          acl.grantee = roles.ingest_oid
          AND acl.privilege_type IN (
              'USAGE',
              'SELECT'
          )
          AND NOT acl.is_grantable
      )
)
SELECT
    pg_catalog.has_database_privilege(
        roles.ingest_oid,
        target_database.oid,
        'CONNECT'
    ),
    pg_catalog.has_database_privilege(
        roles.ingest_oid,
        target_database.oid,
        'CONNECT WITH GRANT OPTION'
    ),
    pg_catalog.has_database_privilege(
        roles.ingest_oid,
        target_database.oid,
        'CREATE'
    ),
    pg_catalog.has_database_privilege(
        roles.ingest_oid,
        target_database.oid,
        'TEMPORARY'
    ),
    pg_catalog.has_database_privilege(
        'public',
        target_database.oid,
        'CONNECT'
    ),
    pg_catalog.has_database_privilege(
        'public',
        target_database.oid,
        'CREATE'
    ),
    pg_catalog.has_database_privilege(
        'public',
        target_database.oid,
        'TEMPORARY'
    ),
    pg_catalog.has_schema_privilege(
        roles.ingest_oid,
        target_schema.oid,
        'USAGE'
    ),
    pg_catalog.has_schema_privilege(
        roles.ingest_oid,
        target_schema.oid,
        'USAGE WITH GRANT OPTION'
    ),
    pg_catalog.has_schema_privilege(
        roles.ingest_oid,
        target_schema.oid,
        'CREATE'
    ),
    pg_catalog.has_schema_privilege(
        'public',
        target_schema.oid,
        'USAGE'
    ),
    pg_catalog.has_schema_privilege(
        'public',
        target_schema.oid,
        'CREATE'
    ),
    pg_catalog.has_schema_privilege(
        'public',
        default_public_schema.oid,
        'CREATE'
    ),
    (
        SELECT count(*)::integer
        FROM target_tables
    ),
    (
        SELECT count(*)::integer
        FROM target_tables
        CROSS JOIN roles
        WHERE pg_catalog.has_table_privilege(
            roles.ingest_oid,
            target_tables.oid,
            'SELECT'
        )
    ),
    (
        SELECT count(*)::integer
        FROM target_tables
        CROSS JOIN roles
        WHERE pg_catalog.has_table_privilege(
            roles.ingest_oid,
            target_tables.oid,
            'INSERT'
        )
    ),
    (
        SELECT count(*)::integer
        FROM target_tables
        CROSS JOIN roles
        WHERE pg_catalog.has_table_privilege(
            roles.ingest_oid,
            target_tables.oid,
            'SELECT WITH GRANT OPTION'
        )
    ),
    (
        SELECT count(*)::integer
        FROM target_tables
        CROSS JOIN roles
        WHERE pg_catalog.has_table_privilege(
            roles.ingest_oid,
            target_tables.oid,
            'INSERT WITH GRANT OPTION'
        )
    ),
    (
        SELECT count(*)::integer
        FROM target_tables
        CROSS JOIN roles
        WHERE pg_catalog.has_table_privilege(
            roles.ingest_oid,
            target_tables.oid,
            'UPDATE'
        )
    ),
    (
        SELECT count(*)::integer
        FROM target_tables
        CROSS JOIN roles
        WHERE pg_catalog.has_table_privilege(
            roles.ingest_oid,
            target_tables.oid,
            'DELETE'
        )
    ),
    (
        SELECT count(*)::integer
        FROM target_tables
        CROSS JOIN roles
        WHERE pg_catalog.has_table_privilege(
            roles.ingest_oid,
            target_tables.oid,
            'TRUNCATE'
        )
    ),
    (
        SELECT count(*)::integer
        FROM target_tables
        CROSS JOIN roles
        WHERE pg_catalog.has_table_privilege(
            roles.ingest_oid,
            target_tables.oid,
            'REFERENCES'
        )
    ),
    (
        SELECT count(*)::integer
        FROM target_tables
        CROSS JOIN roles
        WHERE pg_catalog.has_table_privilege(
            roles.ingest_oid,
            target_tables.oid,
            'TRIGGER'
        )
    ),
    (
        SELECT count(*)::integer
        FROM target_tables
        CROSS JOIN roles
        WHERE pg_catalog.has_table_privilege(
            roles.ingest_oid,
            target_tables.oid,
            'MAINTAIN'
        )
    ),
    (
        SELECT count(*)::integer
        FROM target_tables
        CROSS JOIN roles
        WHERE pg_catalog.has_any_column_privilege(
            roles.ingest_oid,
            target_tables.oid,
            'UPDATE'
        )
    ),
    (
        SELECT count(*)::integer
        FROM target_tables
        CROSS JOIN roles
        WHERE pg_catalog.has_any_column_privilege(
            roles.ingest_oid,
            target_tables.oid,
            'REFERENCES'
        )
    ),
    (
        SELECT count(*)::integer
        FROM target_sequences
    ),
    (
        SELECT count(*)::integer
        FROM target_sequences
        CROSS JOIN roles
        WHERE pg_catalog.has_sequence_privilege(
            roles.ingest_oid,
            target_sequences.oid,
            'USAGE'
        )
    ),
    (
        SELECT count(*)::integer
        FROM target_sequences
        CROSS JOIN roles
        WHERE pg_catalog.has_sequence_privilege(
            roles.ingest_oid,
            target_sequences.oid,
            'SELECT'
        )
    ),
    (
        SELECT count(*)::integer
        FROM target_sequences
        CROSS JOIN roles
        WHERE pg_catalog.has_sequence_privilege(
            roles.ingest_oid,
            target_sequences.oid,
            'USAGE WITH GRANT OPTION'
        )
    ),
    (
        SELECT count(*)::integer
        FROM target_sequences
        CROSS JOIN roles
        WHERE pg_catalog.has_sequence_privilege(
            roles.ingest_oid,
            target_sequences.oid,
            'SELECT WITH GRANT OPTION'
        )
    ),
    (
        SELECT count(*)::integer
        FROM target_sequences
        CROSS JOIN roles
        WHERE pg_catalog.has_sequence_privilege(
            roles.ingest_oid,
            target_sequences.oid,
            'UPDATE'
        )
    ),
    (
        SELECT count FROM database_unexpected
    ) +
    (
        SELECT count FROM schema_unexpected
    ) +
    (
        SELECT count FROM public_schema_unexpected
    ) +
    (
        SELECT count FROM table_unexpected
    ) +
    (
        SELECT count FROM column_unexpected
    ) +
    (
        SELECT count FROM sequence_unexpected
    )
FROM roles
CROSS JOIN target_database
CROSS JOIN target_schema
CROSS JOIN default_public_schema;
`,
		owner,
		ingest,
		database,
		schema,
		schema,
		schema,
	)
}

func observeSORPostgreSQLDatabaseExplicitPrivileges(
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
			buildSORPostgreSQLDatabaseExplicitPrivilegeQuery(
				policy,
			),
			sorPostgreSQLDatabaseExplicitPrivilegeFieldCount,
		)
	if err != nil {
		return sorPostgreSQLDatabasePrivilegeFacts{},
			err
	}

	return parseSORPostgreSQLDatabaseExplicitPrivilegeFacts(
		fields,
	)
}

func parseSORPostgreSQLDatabaseExplicitPrivilegeFacts(
	fields []string,
) (sorPostgreSQLDatabasePrivilegeFacts, error) {
	if len(fields) !=
		sorPostgreSQLDatabaseExplicitPrivilegeFieldCount {
		return sorPostgreSQLDatabasePrivilegeFacts{},
			fmt.Errorf(
				"PostgreSQL explicit privilege field count = %d, want %d",
				len(fields),
				sorPostgreSQLDatabaseExplicitPrivilegeFieldCount,
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

	intField :=
		func(
			index int,
			label string,
		) (int, error) {
			value, err :=
				parseSORPostgreSQLDatabasePSQLInt(
					fields[index],
				)
			if err != nil {
				return 0,
					fmt.Errorf(
						"parse PostgreSQL %s: %w",
						label,
						err,
					)
			}

			if value < 0 {
				return 0,
					fmt.Errorf(
						"PostgreSQL %s returned negative count",
						label,
					)
			}

			return value, nil
		}

	facts :=
		sorPostgreSQLDatabasePrivilegeFacts{}

	var err error

	if facts.DatabaseConnect, err =
		boolField(0, "database CONNECT privilege"); err != nil {
		return sorPostgreSQLDatabasePrivilegeFacts{}, err
	}

	if facts.DatabaseConnectGrantOption, err =
		boolField(1, "database CONNECT grant option"); err != nil {
		return sorPostgreSQLDatabasePrivilegeFacts{}, err
	}

	if facts.DatabaseCreate, err =
		boolField(2, "database CREATE privilege"); err != nil {
		return sorPostgreSQLDatabasePrivilegeFacts{}, err
	}

	if facts.DatabaseTemporary, err =
		boolField(3, "database TEMPORARY privilege"); err != nil {
		return sorPostgreSQLDatabasePrivilegeFacts{}, err
	}

	if facts.PublicDatabaseConnect, err =
		boolField(4, "PUBLIC database CONNECT privilege"); err != nil {
		return sorPostgreSQLDatabasePrivilegeFacts{}, err
	}

	if facts.PublicDatabaseCreate, err =
		boolField(5, "PUBLIC database CREATE privilege"); err != nil {
		return sorPostgreSQLDatabasePrivilegeFacts{}, err
	}

	if facts.PublicDatabaseTemporary, err =
		boolField(6, "PUBLIC database TEMPORARY privilege"); err != nil {
		return sorPostgreSQLDatabasePrivilegeFacts{}, err
	}

	if facts.SchemaUsage, err =
		boolField(7, "schema USAGE privilege"); err != nil {
		return sorPostgreSQLDatabasePrivilegeFacts{}, err
	}

	if facts.SchemaUsageGrantOption, err =
		boolField(8, "schema USAGE grant option"); err != nil {
		return sorPostgreSQLDatabasePrivilegeFacts{}, err
	}

	if facts.SchemaCreate, err =
		boolField(9, "schema CREATE privilege"); err != nil {
		return sorPostgreSQLDatabasePrivilegeFacts{}, err
	}

	if facts.PublicSchemaUsage, err =
		boolField(10, "PUBLIC FI schema USAGE privilege"); err != nil {
		return sorPostgreSQLDatabasePrivilegeFacts{}, err
	}

	if facts.PublicSchemaCreate, err =
		boolField(11, "PUBLIC FI schema CREATE privilege"); err != nil {
		return sorPostgreSQLDatabasePrivilegeFacts{}, err
	}

	if facts.PublicDefaultSchemaCreate, err =
		boolField(12, "PUBLIC default schema CREATE privilege"); err != nil {
		return sorPostgreSQLDatabasePrivilegeFacts{}, err
	}

	if facts.TableCount, err =
		intField(13, "table count"); err != nil {
		return sorPostgreSQLDatabasePrivilegeFacts{}, err
	}

	if facts.TableSelectCount, err =
		intField(14, "table SELECT count"); err != nil {
		return sorPostgreSQLDatabasePrivilegeFacts{}, err
	}

	if facts.TableInsertCount, err =
		intField(15, "table INSERT count"); err != nil {
		return sorPostgreSQLDatabasePrivilegeFacts{}, err
	}

	if facts.TableSelectGrantOptionCount, err =
		intField(16, "table SELECT grant-option count"); err != nil {
		return sorPostgreSQLDatabasePrivilegeFacts{}, err
	}

	if facts.TableInsertGrantOptionCount, err =
		intField(17, "table INSERT grant-option count"); err != nil {
		return sorPostgreSQLDatabasePrivilegeFacts{}, err
	}

	if facts.TableUpdateCount, err =
		intField(18, "table UPDATE count"); err != nil {
		return sorPostgreSQLDatabasePrivilegeFacts{}, err
	}

	if facts.TableDeleteCount, err =
		intField(19, "table DELETE count"); err != nil {
		return sorPostgreSQLDatabasePrivilegeFacts{}, err
	}

	if facts.TableTruncateCount, err =
		intField(20, "table TRUNCATE count"); err != nil {
		return sorPostgreSQLDatabasePrivilegeFacts{}, err
	}

	if facts.TableReferencesCount, err =
		intField(21, "table REFERENCES count"); err != nil {
		return sorPostgreSQLDatabasePrivilegeFacts{}, err
	}

	if facts.TableTriggerCount, err =
		intField(22, "table TRIGGER count"); err != nil {
		return sorPostgreSQLDatabasePrivilegeFacts{}, err
	}

	if facts.TableMaintainCount, err =
		intField(23, "table MAINTAIN count"); err != nil {
		return sorPostgreSQLDatabasePrivilegeFacts{}, err
	}

	if facts.TableColumnUpdateCount, err =
		intField(24, "column UPDATE table count"); err != nil {
		return sorPostgreSQLDatabasePrivilegeFacts{}, err
	}

	if facts.TableColumnReferencesCount, err =
		intField(25, "column REFERENCES table count"); err != nil {
		return sorPostgreSQLDatabasePrivilegeFacts{}, err
	}

	if facts.SequenceCount, err =
		intField(26, "sequence count"); err != nil {
		return sorPostgreSQLDatabasePrivilegeFacts{}, err
	}

	if facts.SequenceUsageCount, err =
		intField(27, "sequence USAGE count"); err != nil {
		return sorPostgreSQLDatabasePrivilegeFacts{}, err
	}

	if facts.SequenceSelectCount, err =
		intField(28, "sequence SELECT count"); err != nil {
		return sorPostgreSQLDatabasePrivilegeFacts{}, err
	}

	if facts.SequenceUsageGrantOptionCount, err =
		intField(29, "sequence USAGE grant-option count"); err != nil {
		return sorPostgreSQLDatabasePrivilegeFacts{}, err
	}

	if facts.SequenceSelectGrantOptionCount, err =
		intField(30, "sequence SELECT grant-option count"); err != nil {
		return sorPostgreSQLDatabasePrivilegeFacts{}, err
	}

	if facts.SequenceUpdateCount, err =
		intField(31, "sequence UPDATE count"); err != nil {
		return sorPostgreSQLDatabasePrivilegeFacts{}, err
	}

	if facts.UnexpectedExplicitACLGrantCount, err =
		intField(32, "unexpected explicit ACL grant count"); err != nil {
		return sorPostgreSQLDatabasePrivilegeFacts{}, err
	}

	return facts, nil
}
