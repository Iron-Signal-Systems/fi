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

func TestGenerateSORPostgreSQLDatabaseCredentialSecretDefaultRandom(
	t *testing.T,
) {
	secret, err :=
		generateSORPostgreSQLDatabaseCredentialSecret(
			nil,
		)
	if err != nil {
		t.Fatalf(
			"generate credential secret: %v",
			err,
		)
	}

	if !isSORPostgreSQLDatabaseCredentialSecret(
		secret,
	) {
		t.Fatalf(
			"generated secret does not satisfy credential contract",
		)
	}
}

func TestGenerateSORPostgreSQLDatabaseCredentialSecretExactEncoding(
	t *testing.T,
) {
	input :=
		make(
			[]byte,
			sorPostgreSQLDatabaseCredentialSecretBytes,
		)

	for index := range input {
		input[index] =
			byte(index)
	}

	secret, err :=
		generateSORPostgreSQLDatabaseCredentialSecret(
			bytes.NewReader(
				input,
			),
		)
	if err != nil {
		t.Fatalf(
			"generate credential secret: %v",
			err,
		)
	}

	expected :=
		"000102030405060708090a0b0c0d0e0f" +
			"101112131415161718191a1b1c1d1e1f"

	if secret != expected {
		t.Fatalf(
			"secret = %q, want %q",
			secret,
			expected,
		)
	}
}

func TestGenerateSORPostgreSQLDatabaseCredentialSecretRequiresFullEntropy(
	t *testing.T,
) {
	reader :=
		io.LimitReader(
			strings.NewReader(
				strings.Repeat(
					"x",
					sorPostgreSQLDatabaseCredentialSecretBytes,
				),
			),
			sorPostgreSQLDatabaseCredentialSecretBytes-1,
		)

	secret, err :=
		generateSORPostgreSQLDatabaseCredentialSecret(
			reader,
		)

	if err == nil {
		t.Fatal(
			"short random source was accepted",
		)
	}

	if secret != "" {
		t.Fatalf(
			"failed generation returned secret material",
		)
	}
}
