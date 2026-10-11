// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"fmt"
	"strings"
)

func buildSORPostgreSQLDatabaseClusterHardeningSQL(
	policy sorPostgreSQLDatabasePolicy,
) ([]byte, error) {
	if err :=
		validateSORPostgreSQLDatabaseBootstrapPolicy(
			policy,
		); err != nil {
		return nil, err
	}

	database, err :=
		quoteSORPostgreSQLDatabaseBootstrapIdentifier(
			policy.DatabaseName,
		)
	if err != nil {
		return nil, err
	}

	comment, err :=
		quoteSORPostgreSQLDatabaseBootstrapLiteral(
			policy.DatabaseComment,
		)
	if err != nil {
		return nil, err
	}

	sql :=
		fmt.Sprintf(
			"BEGIN;\n"+
				"REVOKE ALL ON DATABASE %s FROM PUBLIC;\n"+
				"COMMENT ON DATABASE %s IS %s;\n"+
				"COMMIT;\n",
			database,
			database,
			comment,
		)

	return []byte(sql), nil
}

func buildSORPostgreSQLDatabaseCreateSQL(
	policy sorPostgreSQLDatabasePolicy,
) ([]byte, error) {
	if err :=
		validateSORPostgreSQLDatabaseBootstrapPolicy(
			policy,
		); err != nil {
		return nil, err
	}

	database, err :=
		quoteSORPostgreSQLDatabaseBootstrapIdentifier(
			policy.DatabaseName,
		)
	if err != nil {
		return nil, err
	}

	owner, err :=
		quoteSORPostgreSQLDatabaseBootstrapIdentifier(
			policy.DatabaseOwner,
		)
	if err != nil {
		return nil, err
	}

	encoding, err :=
		quoteSORPostgreSQLDatabaseBootstrapLiteral(
			policy.DatabaseEncoding,
		)
	if err != nil {
		return nil, err
	}

	collate, err :=
		quoteSORPostgreSQLDatabaseBootstrapLiteral(
			policy.DatabaseCollate,
		)
	if err != nil {
		return nil, err
	}

	ctype, err :=
		quoteSORPostgreSQLDatabaseBootstrapLiteral(
			policy.DatabaseCType,
		)
	if err != nil {
		return nil, err
	}

	sql :=
		fmt.Sprintf(
			"CREATE DATABASE %s\n"+
				"    WITH OWNER = %s\n"+
				"    TEMPLATE = template0\n"+
				"    ENCODING = %s\n"+
				"    LC_COLLATE = %s\n"+
				"    LC_CTYPE = %s;\n",
			database,
			owner,
			encoding,
			collate,
			ctype,
		)

	return []byte(sql), nil
}

func buildSORPostgreSQLDatabaseLocalHardeningSQL(
	policy sorPostgreSQLDatabasePolicy,
) ([]byte, error) {
	if err :=
		validateSORPostgreSQLDatabaseBootstrapPolicy(
			policy,
		); err != nil {
		return nil, err
	}

	return []byte(
		"BEGIN;\n" +
			"REVOKE CREATE ON SCHEMA public FROM PUBLIC;\n" +
			"COMMIT;\n",
	), nil
}

func buildSORPostgreSQLDatabaseRoleBootstrapSQL(
	policy sorPostgreSQLDatabasePolicy,
	secret string,
	verifier string,
) ([]byte, error) {
	if err :=
		validateSORPostgreSQLDatabaseBootstrapPolicy(
			policy,
		); err != nil {
		return nil, err
	}

	if !isSORPostgreSQLDatabaseCredentialSecret(
		secret,
	) {
		return nil,
			fmt.Errorf(
				"FI PostgreSQL credential secret is invalid",
			)
	}

	matches, err :=
		verifySORPostgreSQLDatabaseSCRAMSHA256(
			secret,
			verifier,
		)
	if err != nil {
		return nil,
			fmt.Errorf(
				"validate FI PostgreSQL bootstrap SCRAM verifier: %w",
				err,
			)
	}

	if !matches {
		return nil,
			fmt.Errorf(
				"FI PostgreSQL bootstrap SCRAM verifier does not match credential secret",
			)
	}

	owner, err :=
		quoteSORPostgreSQLDatabaseBootstrapIdentifier(
			policy.OwnerRole.Name,
		)
	if err != nil {
		return nil, err
	}

	ingest, err :=
		quoteSORPostgreSQLDatabaseBootstrapIdentifier(
			policy.IngestRole.Name,
		)
	if err != nil {
		return nil, err
	}

	ownerComment, err :=
		quoteSORPostgreSQLDatabaseBootstrapLiteral(
			policy.OwnerRole.Comment,
		)
	if err != nil {
		return nil, err
	}

	ingestComment, err :=
		quoteSORPostgreSQLDatabaseBootstrapLiteral(
			policy.IngestRole.Comment,
		)
	if err != nil {
		return nil, err
	}

	verifierLiteral, err :=
		quoteSORPostgreSQLDatabaseBootstrapLiteral(
			verifier,
		)
	if err != nil {
		return nil, err
	}

	sql :=
		fmt.Sprintf(
			"BEGIN;\n"+
				"CREATE ROLE %s WITH\n"+
				"    NOSUPERUSER\n"+
				"    NOCREATEDB\n"+
				"    NOCREATEROLE\n"+
				"    INHERIT\n"+
				"    NOLOGIN\n"+
				"    NOREPLICATION\n"+
				"    NOBYPASSRLS\n"+
				"    CONNECTION LIMIT -1\n"+
				"    PASSWORD NULL;\n"+
				"COMMENT ON ROLE %s IS %s;\n"+
				"CREATE ROLE %s WITH\n"+
				"    NOSUPERUSER\n"+
				"    NOCREATEDB\n"+
				"    NOCREATEROLE\n"+
				"    INHERIT\n"+
				"    LOGIN\n"+
				"    NOREPLICATION\n"+
				"    NOBYPASSRLS\n"+
				"    CONNECTION LIMIT -1\n"+
				"    PASSWORD %s;\n"+
				"COMMENT ON ROLE %s IS %s;\n"+
				"COMMIT;\n",
			owner,
			owner,
			ownerComment,
			ingest,
			verifierLiteral,
			ingest,
			ingestComment,
		)

	if strings.Contains(
		sql,
		secret,
	) {
		return nil,
			fmt.Errorf(
				"FI PostgreSQL plaintext credential secret entered bootstrap SQL",
			)
	}

	return []byte(sql), nil
}

func buildSORPostgreSQLDatabaseSchemaAuthoritySQL(
	policy sorPostgreSQLDatabasePolicy,
) ([]byte, error) {
	if err :=
		validateSORPostgreSQLDatabaseBootstrapPolicy(
			policy,
		); err != nil {
		return nil, err
	}

	schema, err :=
		quoteSORPostgreSQLDatabaseBootstrapIdentifier(
			policy.SchemaName,
		)
	if err != nil {
		return nil, err
	}

	comment, err :=
		quoteSORPostgreSQLDatabaseBootstrapLiteral(
			policy.SchemaComment,
		)
	if err != nil {
		return nil, err
	}

	sql :=
		fmt.Sprintf(
			"BEGIN;\n"+
				"COMMENT ON SCHEMA %s IS %s;\n"+
				"COMMIT;\n",
			schema,
			comment,
		)

	return []byte(sql), nil
}

func quoteSORPostgreSQLDatabaseBootstrapIdentifier(
	value string,
) (string, error) {
	if value == "" {
		return "",
			fmt.Errorf(
				"PostgreSQL bootstrap identifier is required",
			)
	}

	if strings.ContainsRune(
		value,
		'\x00',
	) {
		return "",
			fmt.Errorf(
				"PostgreSQL bootstrap identifier contains NUL",
			)
	}

	return `"` +
			strings.ReplaceAll(
				value,
				`"`,
				`""`,
			) +
			`"`,
		nil
}

func quoteSORPostgreSQLDatabaseBootstrapLiteral(
	value string,
) (string, error) {
	if strings.ContainsRune(
		value,
		'\x00',
	) {
		return "",
			fmt.Errorf(
				"PostgreSQL bootstrap literal contains NUL",
			)
	}

	return `'` +
			strings.ReplaceAll(
				value,
				`'`,
				`''`,
			) +
			`'`,
		nil
}

func validateSORPostgreSQLDatabaseBootstrapPolicy(
	policy sorPostgreSQLDatabasePolicy,
) error {
	if policy.DatabaseName == "" ||
		policy.DatabaseOwner == "" ||
		policy.DatabaseEncoding == "" ||
		policy.DatabaseCollate == "" ||
		policy.DatabaseCType == "" ||
		policy.DatabaseComment == "" ||
		policy.SchemaName == "" ||
		policy.SchemaOwner == "" ||
		policy.SchemaComment == "" {
		return fmt.Errorf(
			"FI PostgreSQL database bootstrap policy is incomplete",
		)
	}

	if policy.OwnerRole.Name == "" ||
		policy.OwnerRole.Comment == "" ||
		policy.IngestRole.Name == "" ||
		policy.IngestRole.Comment == "" {
		return fmt.Errorf(
			"FI PostgreSQL database role bootstrap policy is incomplete",
		)
	}

	if policy.DatabaseOwner !=
		policy.OwnerRole.Name ||
		policy.SchemaOwner !=
			policy.OwnerRole.Name {
		return fmt.Errorf(
			"FI PostgreSQL owner authority is inconsistent",
		)
	}

	if policy.OwnerRole.Name ==
		policy.IngestRole.Name {
		return fmt.Errorf(
			"FI PostgreSQL owner and ingest roles must be distinct",
		)
	}

	if policy.OwnerRole.Superuser ||
		policy.OwnerRole.CreateDB ||
		policy.OwnerRole.CreateRole ||
		policy.OwnerRole.Replication ||
		policy.OwnerRole.BypassRLS ||
		policy.OwnerRole.CanLogin ||
		policy.OwnerRole.PasswordRequired ||
		!policy.OwnerRole.Inherit ||
		policy.OwnerRole.ConnectionLimit != -1 ||
		!policy.OwnerRole.ValidUntilInfinity {
		return fmt.Errorf(
			"FI PostgreSQL owner role policy is not accepted for bootstrap",
		)
	}

	if policy.IngestRole.Superuser ||
		policy.IngestRole.CreateDB ||
		policy.IngestRole.CreateRole ||
		policy.IngestRole.Replication ||
		policy.IngestRole.BypassRLS ||
		!policy.IngestRole.CanLogin ||
		!policy.IngestRole.PasswordRequired ||
		!policy.IngestRole.Inherit ||
		policy.IngestRole.ConnectionLimit != -1 ||
		!policy.IngestRole.ValidUntilInfinity {
		return fmt.Errorf(
			"FI PostgreSQL ingest role policy is not accepted for bootstrap",
		)
	}

	return nil
}
