// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"bytes"
	"strings"
	"testing"
)

func TestBuildSORPostgreSQLDatabaseCreateSQLExactAuthority(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	sql, err :=
		buildSORPostgreSQLDatabaseCreateSQL(
			policy,
		)
	if err != nil {
		t.Fatalf(
			"build database create SQL: %v",
			err,
		)
	}

	text :=
		string(sql)

	expected :=
		[]string{
			`CREATE DATABASE "fi"`,
			`WITH OWNER = "fi_owner"`,
			`TEMPLATE = template0`,
			`ENCODING = 'UTF8'`,
			`LC_COLLATE = 'C.UTF-8'`,
			`LC_CTYPE = 'C.UTF-8'`,
		}

	for _, fragment := range expected {
		if !strings.Contains(
			text,
			fragment,
		) {
			t.Fatalf(
				"database create SQL missing %q:\n%s",
				fragment,
				text,
			)
		}
	}

	if strings.Contains(
		text,
		"BEGIN",
	) ||
		strings.Contains(
			text,
			"COMMIT",
		) {
		t.Fatalf(
			"CREATE DATABASE SQL entered transaction block:\n%s",
			text,
		)
	}
}

func TestBuildSORPostgreSQLDatabaseHardeningSQLExactAuthority(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	clusterSQL, err :=
		buildSORPostgreSQLDatabaseClusterHardeningSQL(
			policy,
		)
	if err != nil {
		t.Fatalf(
			"build cluster hardening SQL: %v",
			err,
		)
	}

	clusterText :=
		string(clusterSQL)

	if !strings.Contains(
		clusterText,
		`REVOKE ALL ON DATABASE "fi" FROM PUBLIC;`,
	) {
		t.Fatalf(
			"cluster hardening SQL does not revoke PUBLIC database authority:\n%s",
			clusterText,
		)
	}

	if !strings.Contains(
		clusterText,
		`COMMENT ON DATABASE "fi" IS `,
	) ||
		!strings.Contains(
			clusterText,
			policy.DatabaseComment,
		) {
		t.Fatalf(
			"cluster hardening SQL does not establish database authority comment:\n%s",
			clusterText,
		)
	}

	localSQL, err :=
		buildSORPostgreSQLDatabaseLocalHardeningSQL(
			policy,
		)
	if err != nil {
		t.Fatalf(
			"build local hardening SQL: %v",
			err,
		)
	}

	if !strings.Contains(
		string(localSQL),
		"REVOKE CREATE ON SCHEMA public FROM PUBLIC;",
	) {
		t.Fatalf(
			"local hardening SQL does not revoke PUBLIC schema CREATE:\n%s",
			string(localSQL),
		)
	}
}

func TestBuildSORPostgreSQLDatabaseSchemaAuthoritySQLExact(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	sql, err :=
		buildSORPostgreSQLDatabaseSchemaAuthoritySQL(
			policy,
		)
	if err != nil {
		t.Fatalf(
			"build schema authority SQL: %v",
			err,
		)
	}

	text :=
		string(sql)

	if !strings.Contains(
		text,
		`COMMENT ON SCHEMA "fi" IS `,
	) {
		t.Fatalf(
			"schema authority SQL does not comment FI schema:\n%s",
			text,
		)
	}

	if !strings.Contains(
		text,
		policy.SchemaComment,
	) {
		t.Fatalf(
			"schema authority SQL does not contain exact authority comment:\n%s",
			text,
		)
	}

	if strings.Count(
		text,
		"BEGIN;",
	) != 1 ||
		strings.Count(
			text,
			"COMMIT;",
		) != 1 {
		t.Fatalf(
			"schema authority transaction boundary is not exact:\n%s",
			text,
		)
	}
}

func TestBuildSORPostgreSQLDatabaseRoleBootstrapSQLExactAuthority(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	secret :=
		"0123456789abcdef0123456789abcdef" +
			"0123456789abcdef0123456789abcdef"

	salt :=
		bytes.Repeat(
			[]byte{0x5a},
			sorPostgreSQLDatabaseSCRAMSaltBytes,
		)

	verifier, err :=
		generateSORPostgreSQLDatabaseSCRAMVerifier(
			secret,
			bytes.NewReader(
				salt,
			),
		)
	if err != nil {
		t.Fatalf(
			"generate SCRAM verifier: %v",
			err,
		)
	}

	sql, err :=
		buildSORPostgreSQLDatabaseRoleBootstrapSQL(
			policy,
			secret,
			verifier,
		)
	if err != nil {
		t.Fatalf(
			"build role bootstrap SQL: %v",
			err,
		)
	}

	text :=
		string(sql)

	if strings.Contains(
		text,
		secret,
	) {
		t.Fatal(
			"plaintext credential secret entered role bootstrap SQL",
		)
	}

	if !strings.Contains(
		text,
		verifier,
	) {
		t.Fatal(
			"SCRAM verifier absent from role bootstrap SQL",
		)
	}

	expected :=
		[]string{
			`CREATE ROLE "fi_owner" WITH`,
			`NOLOGIN`,
			`PASSWORD NULL;`,
			`COMMENT ON ROLE "fi_owner" IS `,
			`CREATE ROLE "fi_ingest" WITH`,
			`LOGIN`,
			`PASSWORD 'SCRAM-SHA-256$`,
			`COMMENT ON ROLE "fi_ingest" IS `,
			`NOSUPERUSER`,
			`NOCREATEDB`,
			`NOCREATEROLE`,
			`INHERIT`,
			`NOREPLICATION`,
			`NOBYPASSRLS`,
			`CONNECTION LIMIT -1`,
		}

	for _, fragment := range expected {
		if !strings.Contains(
			text,
			fragment,
		) {
			t.Fatalf(
				"role bootstrap SQL missing %q:\n%s",
				fragment,
				text,
			)
		}
	}

	if strings.Contains(
		text,
		"VALID UNTIL",
	) {
		t.Fatalf(
			"role bootstrap SQL explicitly set VALID UNTIL:\n%s",
			text,
		)
	}

	if strings.Contains(
		text,
		"GRANT ",
	) ||
		strings.Contains(
			text,
			" IN ROLE ",
		) {
		t.Fatalf(
			"role bootstrap SQL created role membership:\n%s",
			text,
		)
	}

	if strings.Count(
		text,
		"BEGIN;",
	) != 1 ||
		strings.Count(
			text,
			"COMMIT;",
		) != 1 {
		t.Fatalf(
			"role bootstrap transaction boundary is not exact:\n%s",
			text,
		)
	}
}

func TestBuildSORPostgreSQLDatabaseRoleBootstrapSQLRejectsVerifierMismatch(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	secret :=
		"0123456789abcdef0123456789abcdef" +
			"0123456789abcdef0123456789abcdef"

	otherSecret :=
		"abcdef0123456789abcdef0123456789" +
			"abcdef0123456789abcdef0123456789"

	verifier, err :=
		generateSORPostgreSQLDatabaseSCRAMVerifier(
			otherSecret,
			bytes.NewReader(
				bytes.Repeat(
					[]byte{0x42},
					sorPostgreSQLDatabaseSCRAMSaltBytes,
				),
			),
		)
	if err != nil {
		t.Fatalf(
			"generate mismatched verifier: %v",
			err,
		)
	}

	if _, err :=
		buildSORPostgreSQLDatabaseRoleBootstrapSQL(
			policy,
			secret,
			verifier,
		); err == nil {
		t.Fatal(
			"mismatched SCRAM verifier was accepted",
		)
	}
}

func TestQuoteSORPostgreSQLDatabaseBootstrapIdentifier(
	t *testing.T,
) {
	quoted, err :=
		quoteSORPostgreSQLDatabaseBootstrapIdentifier(
			`role"name`,
		)
	if err != nil {
		t.Fatalf(
			"quote identifier: %v",
			err,
		)
	}

	if quoted !=
		`"role""name"` {
		t.Fatalf(
			"quoted identifier = %q",
			quoted,
		)
	}

	if _, err :=
		quoteSORPostgreSQLDatabaseBootstrapIdentifier(
			"bad\x00name",
		); err == nil {
		t.Fatal(
			"identifier containing NUL was accepted",
		)
	}
}

func TestQuoteSORPostgreSQLDatabaseBootstrapLiteral(
	t *testing.T,
) {
	quoted, err :=
		quoteSORPostgreSQLDatabaseBootstrapLiteral(
			"FI's role",
		)
	if err != nil {
		t.Fatalf(
			"quote literal: %v",
			err,
		)
	}

	if quoted !=
		`'FI''s role'` {
		t.Fatalf(
			"quoted literal = %q",
			quoted,
		)
	}

	if _, err :=
		quoteSORPostgreSQLDatabaseBootstrapLiteral(
			"bad\x00value",
		); err == nil {
		t.Fatal(
			"literal containing NUL was accepted",
		)
	}
}

func TestValidateSORPostgreSQLDatabaseBootstrapPolicyRejectsPrivilegeExpansion(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	policy.IngestRole.Superuser = true

	if err :=
		validateSORPostgreSQLDatabaseBootstrapPolicy(
			policy,
		); err == nil {
		t.Fatal(
			"privileged ingest role bootstrap policy was accepted",
		)
	}
}
