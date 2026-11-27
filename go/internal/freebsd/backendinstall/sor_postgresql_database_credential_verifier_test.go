// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestGenerateSORPostgreSQLDatabaseSCRAMVerifierDefaultRandom(
	t *testing.T,
) {
	secret :=
		"0123456789abcdef0123456789abcdef" +
			"0123456789abcdef0123456789abcdef"

	verifier, err :=
		generateSORPostgreSQLDatabaseSCRAMVerifier(
			secret,
			nil,
		)
	if err != nil {
		t.Fatalf(
			"generate SCRAM verifier: %v",
			err,
		)
	}

	matches, err :=
		verifySORPostgreSQLDatabaseSCRAMSHA256(
			secret,
			verifier,
		)
	if err != nil {
		t.Fatalf(
			"verify generated SCRAM verifier: %v",
			err,
		)
	}

	if !matches {
		t.Fatal(
			"generated SCRAM verifier does not match secret",
		)
	}
}

func TestGenerateSORPostgreSQLDatabaseSCRAMVerifierExact(
	t *testing.T,
) {
	secret :=
		"0123456789abcdef0123456789abcdef" +
			"0123456789abcdef0123456789abcdef"

	salt :=
		make(
			[]byte,
			sorPostgreSQLDatabaseSCRAMSaltBytes,
		)

	for index := range salt {
		salt[index] =
			byte(index)
	}

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

	expected :=
		"SCRAM-SHA-256$4096:" +
			"AAECAwQFBgcICQoLDA0ODw==$" +
			"TX7+UsrUBzwTduL9bIMwpuJPwYfRDYpqrxHg2uTRAgE=:" +
			"aYgdktib+LCYPSZ1/ognnmdY1b6RltHVRA6R52w9gcg="

	if verifier != expected {
		t.Fatalf(
			"verifier = %q, want %q",
			verifier,
			expected,
		)
	}
}

func TestGenerateSORPostgreSQLDatabaseSCRAMVerifierRejectsInvalidSecret(
	t *testing.T,
) {
	verifier, err :=
		generateSORPostgreSQLDatabaseSCRAMVerifier(
			"not-a-valid-secret",
			strings.NewReader(
				strings.Repeat(
					"x",
					sorPostgreSQLDatabaseSCRAMSaltBytes,
				),
			),
		)

	if err == nil {
		t.Fatal(
			"invalid credential secret was accepted",
		)
	}

	if verifier != "" {
		t.Fatal(
			"failed SCRAM generation returned verifier material",
		)
	}
}

func TestGenerateSORPostgreSQLDatabaseSCRAMVerifierRequiresFullSalt(
	t *testing.T,
) {
	secret :=
		"0123456789abcdef0123456789abcdef" +
			"0123456789abcdef0123456789abcdef"

	reader :=
		io.LimitReader(
			strings.NewReader(
				strings.Repeat(
					"x",
					sorPostgreSQLDatabaseSCRAMSaltBytes,
				),
			),
			sorPostgreSQLDatabaseSCRAMSaltBytes-1,
		)

	verifier, err :=
		generateSORPostgreSQLDatabaseSCRAMVerifier(
			secret,
			reader,
		)

	if err == nil {
		t.Fatal(
			"short SCRAM salt source was accepted",
		)
	}

	if verifier != "" {
		t.Fatal(
			"failed SCRAM generation returned verifier material",
		)
	}
}
