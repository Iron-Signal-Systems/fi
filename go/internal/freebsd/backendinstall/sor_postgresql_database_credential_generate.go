// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

const (
	sorPostgreSQLDatabaseCredentialSecretBytes = 32
)

func generateSORPostgreSQLDatabaseCredentialSecret(
	random io.Reader,
) (string, error) {
	if random == nil {
		random = rand.Reader
	}

	value :=
		make(
			[]byte,
			sorPostgreSQLDatabaseCredentialSecretBytes,
		)

	if _, err :=
		io.ReadFull(
			random,
			value,
		); err != nil {
		return "",
			fmt.Errorf(
				"generate FI PostgreSQL credential secret: %w",
				err,
			)
	}

	secret :=
		hex.EncodeToString(
			value,
		)

	if !isSORPostgreSQLDatabaseCredentialSecret(
		secret,
	) {
		return "",
			fmt.Errorf(
				"generated FI PostgreSQL credential secret is invalid",
			)
	}

	return secret, nil
}
