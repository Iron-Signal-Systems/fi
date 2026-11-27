// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import "fmt"

const (
	sorPostgreSQLDatabaseCredentialFieldCount = 2

	sorPostgreSQLDatabaseSCRAMValidationSecret = "00000000000000000000000000000000" +
		"00000000000000000000000000000000"
)

func buildSORPostgreSQLDatabaseCredentialQuery(
	policy sorPostgreSQLDatabasePolicy,
) string {
	role :=
		quoteSORPostgreSQLDatabaseSQLLiteral(
			policy.IngestRole.Name,
		)

	return fmt.Sprintf(`
WITH target_role AS (
    SELECT rolpassword
    FROM pg_catalog.pg_authid
    WHERE rolname = %s
)
SELECT
    EXISTS(
        SELECT 1
        FROM target_role
    ),
    COALESCE(
        (
            SELECT rolpassword
            FROM target_role
        ),
        ''
    );
`,
		role,
	)
}

func observeSORPostgreSQLDatabaseCredentialAndPassfile(
	query func(
		string,
		string,
		int,
	) ([]string, error),
	inspectPassfile func(
		sorPostgreSQLDatabasePolicy,
	) (
		sorPostgreSQLDatabasePassfileFacts,
		string,
		error,
	),
	policy sorPostgreSQLDatabasePolicy,
	catalog sorPostgreSQLDatabaseCatalogFacts,
) (
	sorPostgreSQLDatabaseCredentialFacts,
	sorPostgreSQLDatabasePassfileFacts,
	error,
) {
	fields, err :=
		query(
			"postgres",
			buildSORPostgreSQLDatabaseCredentialQuery(
				policy,
			),
			sorPostgreSQLDatabaseCredentialFieldCount,
		)
	if err != nil {
		return sorPostgreSQLDatabaseCredentialFacts{},
			sorPostgreSQLDatabasePassfileFacts{},
			fmt.Errorf(
				"observe PostgreSQL ingest credential catalog: %w",
				err,
			)
	}

	roleExists,
		verifier,
		err :=
		parseSORPostgreSQLDatabaseCredentialFields(
			fields,
		)
	if err != nil {
		return sorPostgreSQLDatabaseCredentialFacts{},
			sorPostgreSQLDatabasePassfileFacts{},
			err
	}

	passwordPresent :=
		verifier != ""

	if roleExists !=
		catalog.IngestRole.Exists {
		return sorPostgreSQLDatabaseCredentialFacts{},
			sorPostgreSQLDatabasePassfileFacts{},
			fmt.Errorf(
				"PostgreSQL ingest role changed during credential observation",
			)
	}

	if roleExists &&
		passwordPresent !=
			catalog.IngestRole.PasswordPresent {
		return sorPostgreSQLDatabaseCredentialFacts{},
			sorPostgreSQLDatabasePassfileFacts{},
			fmt.Errorf(
				"PostgreSQL ingest password state changed during credential observation",
			)
	}

	passfile,
		secret,
		err :=
		inspectPassfile(
			policy,
		)
	if err != nil {
		return sorPostgreSQLDatabaseCredentialFacts{},
			sorPostgreSQLDatabasePassfileFacts{},
			fmt.Errorf(
				"observe PostgreSQL ingest passfile: %w",
				err,
			)
	}

	facts :=
		sorPostgreSQLDatabaseCredentialFacts{
			Observed:        true,
			PasswordPresent: passwordPresent,
			RoleExists:      roleExists,
		}

	if !roleExists ||
		!passwordPresent {
		return facts,
			passfile,
			nil
	}

	_, verifierErr :=
		verifySORPostgreSQLDatabaseSCRAMSHA256(
			sorPostgreSQLDatabaseSCRAMValidationSecret,
			verifier,
		)

	if verifierErr != nil {
		return facts,
			passfile,
			nil
	}

	facts.SCRAMSHA256 = true

	if !passfile.SecretValid {
		return facts,
			passfile,
			nil
	}

	matches, err :=
		verifySORPostgreSQLDatabaseSCRAMSHA256(
			secret,
			verifier,
		)
	if err != nil {
		return sorPostgreSQLDatabaseCredentialFacts{},
			sorPostgreSQLDatabasePassfileFacts{},
			fmt.Errorf(
				"verify PostgreSQL ingest SCRAM credential",
			)
	}

	facts.MatchesPassfile =
		matches

	return facts,
		passfile,
		nil
}

func parseSORPostgreSQLDatabaseCredentialFields(
	fields []string,
) (
	bool,
	string,
	error,
) {
	if len(fields) !=
		sorPostgreSQLDatabaseCredentialFieldCount {
		return false,
			"",
			fmt.Errorf(
				"PostgreSQL credential field count = %d, want %d",
				len(fields),
				sorPostgreSQLDatabaseCredentialFieldCount,
			)
	}

	roleExists, err :=
		parseSORPostgreSQLDatabasePSQLBool(
			fields[0],
		)
	if err != nil {
		return false,
			"",
			fmt.Errorf(
				"parse PostgreSQL credential role existence: %w",
				err,
			)
	}

	verifier :=
		fields[1]

	if !roleExists &&
		verifier != "" {
		return false,
			"",
			fmt.Errorf(
				"PostgreSQL absent ingest role returned credential data",
			)
	}

	return roleExists,
		verifier,
		nil
}
