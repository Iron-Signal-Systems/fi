// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"fmt"
	"strings"
)

const (
	sorPostgreSQLDatabaseCatalogDatabaseFieldCount   = 6
	sorPostgreSQLDatabaseCatalogFoundationFieldCount = 3
	sorPostgreSQLDatabaseCatalogRoleFieldCount       = 14
	sorPostgreSQLDatabaseCatalogSchemaFieldCount     = 3
)

type sorPostgreSQLDatabaseCatalogObserver struct {
	query func(
		string,
		string,
		int,
	) ([]string, error)
}

func (
	observer sorPostgreSQLDatabaseCatalogObserver,
) Observe(
	policy sorPostgreSQLDatabasePolicy,
) (sorPostgreSQLDatabaseCatalogFacts, error) {
	query := observer.query

	if query == nil {
		executor :=
			sorPostgreSQLDatabaseQueryExecutor{}

		query = executor.Query
	}

	ownerRole, err :=
		observeSORPostgreSQLDatabaseCatalogRole(
			query,
			policy.OwnerRole.Name,
		)
	if err != nil {
		return sorPostgreSQLDatabaseCatalogFacts{},
			fmt.Errorf(
				"observe PostgreSQL owner role: %w",
				err,
			)
	}

	ingestRole, err :=
		observeSORPostgreSQLDatabaseCatalogRole(
			query,
			policy.IngestRole.Name,
		)
	if err != nil {
		return sorPostgreSQLDatabaseCatalogFacts{},
			fmt.Errorf(
				"observe PostgreSQL ingest role: %w",
				err,
			)
	}

	database, err :=
		observeSORPostgreSQLDatabaseCatalogDatabase(
			query,
			policy.DatabaseName,
		)
	if err != nil {
		return sorPostgreSQLDatabaseCatalogFacts{},
			fmt.Errorf(
				"observe PostgreSQL FI database: %w",
				err,
			)
	}

	facts :=
		sorPostgreSQLDatabaseCatalogFacts{
			Database:   database,
			IngestRole: ingestRole,
			OwnerRole:  ownerRole,
		}

	if !database.Exists {
		return facts, nil
	}

	schema, err :=
		observeSORPostgreSQLDatabaseCatalogSchema(
			query,
			policy.DatabaseName,
			policy.SchemaName,
		)
	if err != nil {
		return sorPostgreSQLDatabaseCatalogFacts{},
			fmt.Errorf(
				"observe PostgreSQL FI schema: %w",
				err,
			)
	}

	facts.Schema = schema

	if !schema.Exists {
		return facts, nil
	}

	foundation, err :=
		observeSORPostgreSQLDatabaseCatalogFoundation(
			query,
			policy,
		)
	if err != nil {
		return sorPostgreSQLDatabaseCatalogFacts{},
			fmt.Errorf(
				"observe PostgreSQL relational foundation: %w",
				err,
			)
	}

	foundation.Exists = true
	foundation.SchemaComment = schema.Comment
	facts.Foundation = foundation

	return facts, nil
}

func buildSORPostgreSQLDatabaseCatalogDatabaseQuery(
	databaseName string,
) string {
	database :=
		quoteSORPostgreSQLDatabaseSQLLiteral(
			databaseName,
		)

	return fmt.Sprintf(`
WITH target AS (
    SELECT
        oid,
        datdba,
        encoding,
        datcollate,
        datctype
    FROM pg_catalog.pg_database
    WHERE datname = %s
)
SELECT
    EXISTS(SELECT 1 FROM target),
    COALESCE(
        (SELECT pg_catalog.pg_get_userbyid(datdba) FROM target),
        ''
    ),
    COALESCE(
        (SELECT pg_catalog.pg_encoding_to_char(encoding) FROM target),
        ''
    ),
    COALESCE((SELECT datcollate FROM target), ''),
    COALESCE((SELECT datctype FROM target), ''),
    COALESCE(
        (
            SELECT pg_catalog.shobj_description(
                oid,
                'pg_database'
            )
            FROM target
        ),
        ''
    );
`,
		database,
	)
}

func buildSORPostgreSQLDatabaseCatalogFoundationQuery(
	policy sorPostgreSQLDatabasePolicy,
) (string, error) {
	if len(policy.CoreTables) == 0 {
		return "",
			fmt.Errorf(
				"PostgreSQL relational foundation requires core tables",
			)
	}

	values :=
		make(
			[]string,
			0,
			len(policy.CoreTables),
		)

	seen :=
		make(
			map[string]struct{},
			len(policy.CoreTables),
		)

	for _, tableName := range policy.CoreTables {
		if tableName == "" {
			return "",
				fmt.Errorf(
					"PostgreSQL relational foundation contains empty core table name",
				)
		}

		if _, exists :=
			seen[tableName]; exists {
			return "",
				fmt.Errorf(
					"PostgreSQL relational foundation contains duplicate core table %q",
					tableName,
				)
		}

		seen[tableName] =
			struct{}{}

		values =
			append(
				values,
				"("+
					quoteSORPostgreSQLDatabaseSQLLiteral(
						tableName,
					)+
					")",
			)
	}

	schema :=
		quoteSORPostgreSQLDatabaseSQLLiteral(
			policy.SchemaName,
		)

	return fmt.Sprintf(`
SELECT
    (
        SELECT count(*)::integer
        FROM information_schema.tables
        WHERE table_schema = %s
          AND table_type = 'BASE TABLE'
    ),
    (
        SELECT count(*)::integer
        FROM information_schema.columns
        WHERE table_schema = %s
          AND data_type IN ('json', 'jsonb', 'xml')
    ),
    (
        SELECT count(*)::integer
        FROM (
            VALUES %s
        ) AS required(table_name)
        WHERE NOT EXISTS (
            SELECT 1
            FROM information_schema.tables AS observed
            WHERE observed.table_schema = %s
              AND observed.table_type = 'BASE TABLE'
              AND observed.table_name = required.table_name
        )
    );
`,
			schema,
			schema,
			strings.Join(
				values,
				", ",
			),
			schema,
		),
		nil
}

func buildSORPostgreSQLDatabaseCatalogRoleQuery(
	roleName string,
) string {
	role :=
		quoteSORPostgreSQLDatabaseSQLLiteral(
			roleName,
		)

	return fmt.Sprintf(`
WITH target AS (
    SELECT
        oid,
        rolbypassrls,
        rolcanlogin,
        rolconnlimit,
        rolcreatedb,
        rolcreaterole,
        rolinherit,
        rolpassword,
        rolreplication,
        rolsuper,
        rolvaliduntil
    FROM pg_catalog.pg_authid
    WHERE rolname = %s
)
SELECT
    EXISTS(SELECT 1 FROM target),
    COALESCE((SELECT rolbypassrls FROM target), false),
    COALESCE((SELECT rolcanlogin FROM target), false),
    COALESCE(
        (
            SELECT pg_catalog.shobj_description(
                oid,
                'pg_authid'
            )
            FROM target
        ),
        ''
    ),
    COALESCE((SELECT rolconnlimit FROM target), 0),
    COALESCE((SELECT rolcreatedb FROM target), false),
    COALESCE((SELECT rolcreaterole FROM target), false),
    COALESCE(
        (
            SELECT count(*)::integer
            FROM pg_catalog.pg_auth_members AS membership
            JOIN target
              ON membership.roleid = target.oid
        ),
        0
    ),
    COALESCE((SELECT rolinherit FROM target), false),
    COALESCE(
        (
            SELECT count(*)::integer
            FROM pg_catalog.pg_auth_members AS membership
            JOIN target
              ON membership.member = target.oid
        ),
        0
    ),
    COALESCE(
        (SELECT rolpassword IS NOT NULL FROM target),
        false
    ),
    COALESCE((SELECT rolreplication FROM target), false),
    COALESCE((SELECT rolsuper FROM target), false),
    COALESCE(
        (SELECT rolvaliduntil IS NULL FROM target),
        false
    );
`,
		role,
	)
}

func buildSORPostgreSQLDatabaseCatalogSchemaQuery(
	schemaName string,
) string {
	schema :=
		quoteSORPostgreSQLDatabaseSQLLiteral(
			schemaName,
		)

	return fmt.Sprintf(`
WITH target AS (
    SELECT
        oid,
        nspowner
    FROM pg_catalog.pg_namespace
    WHERE nspname = %s
)
SELECT
    EXISTS(SELECT 1 FROM target),
    COALESCE(
        (SELECT pg_catalog.pg_get_userbyid(nspowner) FROM target),
        ''
    ),
    COALESCE(
        (
            SELECT pg_catalog.obj_description(
                oid,
                'pg_namespace'
            )
            FROM target
        ),
        ''
    );
`,
		schema,
	)
}

func observeSORPostgreSQLDatabaseCatalogDatabase(
	query func(
		string,
		string,
		int,
	) ([]string, error),
	databaseName string,
) (sorPostgreSQLDatabaseCatalogDatabaseFacts, error) {
	fields, err :=
		query(
			"postgres",
			buildSORPostgreSQLDatabaseCatalogDatabaseQuery(
				databaseName,
			),
			sorPostgreSQLDatabaseCatalogDatabaseFieldCount,
		)
	if err != nil {
		return sorPostgreSQLDatabaseCatalogDatabaseFacts{},
			err
	}

	return parseSORPostgreSQLDatabaseCatalogDatabaseFacts(
		fields,
	)
}

func observeSORPostgreSQLDatabaseCatalogFoundation(
	query func(
		string,
		string,
		int,
	) ([]string, error),
	policy sorPostgreSQLDatabasePolicy,
) (sorPostgreSQLDatabaseCatalogFoundationFacts, error) {
	sql, err :=
		buildSORPostgreSQLDatabaseCatalogFoundationQuery(
			policy,
		)
	if err != nil {
		return sorPostgreSQLDatabaseCatalogFoundationFacts{},
			err
	}

	fields, err :=
		query(
			policy.DatabaseName,
			sql,
			sorPostgreSQLDatabaseCatalogFoundationFieldCount,
		)
	if err != nil {
		return sorPostgreSQLDatabaseCatalogFoundationFacts{},
			err
	}

	return parseSORPostgreSQLDatabaseCatalogFoundationFacts(
		fields,
	)
}

func observeSORPostgreSQLDatabaseCatalogRole(
	query func(
		string,
		string,
		int,
	) ([]string, error),
	roleName string,
) (sorPostgreSQLDatabaseCatalogRoleFacts, error) {
	fields, err :=
		query(
			"postgres",
			buildSORPostgreSQLDatabaseCatalogRoleQuery(
				roleName,
			),
			sorPostgreSQLDatabaseCatalogRoleFieldCount,
		)
	if err != nil {
		return sorPostgreSQLDatabaseCatalogRoleFacts{},
			err
	}

	return parseSORPostgreSQLDatabaseCatalogRoleFacts(
		fields,
	)
}

func observeSORPostgreSQLDatabaseCatalogSchema(
	query func(
		string,
		string,
		int,
	) ([]string, error),
	databaseName string,
	schemaName string,
) (sorPostgreSQLDatabaseCatalogSchemaFacts, error) {
	fields, err :=
		query(
			databaseName,
			buildSORPostgreSQLDatabaseCatalogSchemaQuery(
				schemaName,
			),
			sorPostgreSQLDatabaseCatalogSchemaFieldCount,
		)
	if err != nil {
		return sorPostgreSQLDatabaseCatalogSchemaFacts{},
			err
	}

	return parseSORPostgreSQLDatabaseCatalogSchemaFacts(
		fields,
	)
}

func parseSORPostgreSQLDatabaseCatalogDatabaseFacts(
	fields []string,
) (sorPostgreSQLDatabaseCatalogDatabaseFacts, error) {
	if len(fields) !=
		sorPostgreSQLDatabaseCatalogDatabaseFieldCount {
		return sorPostgreSQLDatabaseCatalogDatabaseFacts{},
			fmt.Errorf(
				"PostgreSQL database catalog field count = %d, want %d",
				len(fields),
				sorPostgreSQLDatabaseCatalogDatabaseFieldCount,
			)
	}

	exists, err :=
		parseSORPostgreSQLDatabasePSQLBool(
			fields[0],
		)
	if err != nil {
		return sorPostgreSQLDatabaseCatalogDatabaseFacts{},
			fmt.Errorf(
				"parse PostgreSQL database existence: %w",
				err,
			)
	}

	return sorPostgreSQLDatabaseCatalogDatabaseFacts{
			Collate:  fields[3],
			Comment:  fields[5],
			CType:    fields[4],
			Encoding: fields[2],
			Exists:   exists,
			Owner:    fields[1],
		},
		nil
}

func parseSORPostgreSQLDatabaseCatalogFoundationFacts(
	fields []string,
) (sorPostgreSQLDatabaseCatalogFoundationFacts, error) {
	if len(fields) !=
		sorPostgreSQLDatabaseCatalogFoundationFieldCount {
		return sorPostgreSQLDatabaseCatalogFoundationFacts{},
			fmt.Errorf(
				"PostgreSQL foundation catalog field count = %d, want %d",
				len(fields),
				sorPostgreSQLDatabaseCatalogFoundationFieldCount,
			)
	}

	tableCount, err :=
		parseSORPostgreSQLDatabasePSQLInt(
			fields[0],
		)
	if err != nil {
		return sorPostgreSQLDatabaseCatalogFoundationFacts{},
			fmt.Errorf(
				"parse PostgreSQL relational table count: %w",
				err,
			)
	}

	badTypedColumns, err :=
		parseSORPostgreSQLDatabasePSQLInt(
			fields[1],
		)
	if err != nil {
		return sorPostgreSQLDatabaseCatalogFoundationFacts{},
			fmt.Errorf(
				"parse PostgreSQL bad typed column count: %w",
				err,
			)
	}

	missingCoreTables, err :=
		parseSORPostgreSQLDatabasePSQLInt(
			fields[2],
		)
	if err != nil {
		return sorPostgreSQLDatabaseCatalogFoundationFacts{},
			fmt.Errorf(
				"parse PostgreSQL missing core table count: %w",
				err,
			)
	}

	if tableCount < 0 ||
		badTypedColumns < 0 ||
		missingCoreTables < 0 {
		return sorPostgreSQLDatabaseCatalogFoundationFacts{},
			fmt.Errorf(
				"PostgreSQL relational foundation returned negative count",
			)
	}

	return sorPostgreSQLDatabaseCatalogFoundationFacts{
			BadTypedColumns:   badTypedColumns,
			MissingCoreTables: missingCoreTables,
			TableCount:        tableCount,
		},
		nil
}

func parseSORPostgreSQLDatabaseCatalogRoleFacts(
	fields []string,
) (sorPostgreSQLDatabaseCatalogRoleFacts, error) {
	if len(fields) !=
		sorPostgreSQLDatabaseCatalogRoleFieldCount {
		return sorPostgreSQLDatabaseCatalogRoleFacts{},
			fmt.Errorf(
				"PostgreSQL role catalog field count = %d, want %d",
				len(fields),
				sorPostgreSQLDatabaseCatalogRoleFieldCount,
			)
	}

	exists, err :=
		parseSORPostgreSQLDatabasePSQLBool(
			fields[0],
		)
	if err != nil {
		return sorPostgreSQLDatabaseCatalogRoleFacts{},
			fmt.Errorf(
				"parse PostgreSQL role existence: %w",
				err,
			)
	}

	bypassRLS, err :=
		parseSORPostgreSQLDatabasePSQLBool(
			fields[1],
		)
	if err != nil {
		return sorPostgreSQLDatabaseCatalogRoleFacts{},
			fmt.Errorf(
				"parse PostgreSQL role BYPASSRLS: %w",
				err,
			)
	}

	canLogin, err :=
		parseSORPostgreSQLDatabasePSQLBool(
			fields[2],
		)
	if err != nil {
		return sorPostgreSQLDatabaseCatalogRoleFacts{},
			fmt.Errorf(
				"parse PostgreSQL role LOGIN: %w",
				err,
			)
	}

	connectionLimit, err :=
		parseSORPostgreSQLDatabasePSQLInt(
			fields[4],
		)
	if err != nil {
		return sorPostgreSQLDatabaseCatalogRoleFacts{},
			fmt.Errorf(
				"parse PostgreSQL role connection limit: %w",
				err,
			)
	}

	createDB, err :=
		parseSORPostgreSQLDatabasePSQLBool(
			fields[5],
		)
	if err != nil {
		return sorPostgreSQLDatabaseCatalogRoleFacts{},
			fmt.Errorf(
				"parse PostgreSQL role CREATEDB: %w",
				err,
			)
	}

	createRole, err :=
		parseSORPostgreSQLDatabasePSQLBool(
			fields[6],
		)
	if err != nil {
		return sorPostgreSQLDatabaseCatalogRoleFacts{},
			fmt.Errorf(
				"parse PostgreSQL role CREATEROLE: %w",
				err,
			)
	}

	grantedToCount, err :=
		parseSORPostgreSQLDatabasePSQLInt(
			fields[7],
		)
	if err != nil {
		return sorPostgreSQLDatabaseCatalogRoleFacts{},
			fmt.Errorf(
				"parse PostgreSQL role granted-to count: %w",
				err,
			)
	}

	inherit, err :=
		parseSORPostgreSQLDatabasePSQLBool(
			fields[8],
		)
	if err != nil {
		return sorPostgreSQLDatabaseCatalogRoleFacts{},
			fmt.Errorf(
				"parse PostgreSQL role INHERIT: %w",
				err,
			)
	}

	memberOfCount, err :=
		parseSORPostgreSQLDatabasePSQLInt(
			fields[9],
		)
	if err != nil {
		return sorPostgreSQLDatabaseCatalogRoleFacts{},
			fmt.Errorf(
				"parse PostgreSQL role member-of count: %w",
				err,
			)
	}

	passwordPresent, err :=
		parseSORPostgreSQLDatabasePSQLBool(
			fields[10],
		)
	if err != nil {
		return sorPostgreSQLDatabaseCatalogRoleFacts{},
			fmt.Errorf(
				"parse PostgreSQL role password presence: %w",
				err,
			)
	}

	replication, err :=
		parseSORPostgreSQLDatabasePSQLBool(
			fields[11],
		)
	if err != nil {
		return sorPostgreSQLDatabaseCatalogRoleFacts{},
			fmt.Errorf(
				"parse PostgreSQL role REPLICATION: %w",
				err,
			)
	}

	superuser, err :=
		parseSORPostgreSQLDatabasePSQLBool(
			fields[12],
		)
	if err != nil {
		return sorPostgreSQLDatabaseCatalogRoleFacts{},
			fmt.Errorf(
				"parse PostgreSQL role SUPERUSER: %w",
				err,
			)
	}

	validUntilInfinity, err :=
		parseSORPostgreSQLDatabasePSQLBool(
			fields[13],
		)
	if err != nil {
		return sorPostgreSQLDatabaseCatalogRoleFacts{},
			fmt.Errorf(
				"parse PostgreSQL role password lifetime: %w",
				err,
			)
	}

	if grantedToCount < 0 ||
		memberOfCount < 0 {
		return sorPostgreSQLDatabaseCatalogRoleFacts{},
			fmt.Errorf(
				"PostgreSQL role membership returned negative count",
			)
	}

	return sorPostgreSQLDatabaseCatalogRoleFacts{
			BypassRLS:          bypassRLS,
			CanLogin:           canLogin,
			Comment:            fields[3],
			ConnectionLimit:    connectionLimit,
			CreateDB:           createDB,
			CreateRole:         createRole,
			Exists:             exists,
			GrantedToCount:     grantedToCount,
			Inherit:            inherit,
			MemberOfCount:      memberOfCount,
			PasswordPresent:    passwordPresent,
			Replication:        replication,
			Superuser:          superuser,
			ValidUntilInfinity: validUntilInfinity,
		},
		nil
}

func parseSORPostgreSQLDatabaseCatalogSchemaFacts(
	fields []string,
) (sorPostgreSQLDatabaseCatalogSchemaFacts, error) {
	if len(fields) !=
		sorPostgreSQLDatabaseCatalogSchemaFieldCount {
		return sorPostgreSQLDatabaseCatalogSchemaFacts{},
			fmt.Errorf(
				"PostgreSQL schema catalog field count = %d, want %d",
				len(fields),
				sorPostgreSQLDatabaseCatalogSchemaFieldCount,
			)
	}

	exists, err :=
		parseSORPostgreSQLDatabasePSQLBool(
			fields[0],
		)
	if err != nil {
		return sorPostgreSQLDatabaseCatalogSchemaFacts{},
			fmt.Errorf(
				"parse PostgreSQL schema existence: %w",
				err,
			)
	}

	return sorPostgreSQLDatabaseCatalogSchemaFacts{
			Comment: fields[2],
			Exists:  exists,
			Owner:   fields[1],
		},
		nil
}

func quoteSORPostgreSQLDatabaseSQLLiteral(
	value string,
) string {
	return "'" +
		strings.ReplaceAll(
			value,
			"'",
			"''",
		) +
		"'"
}
