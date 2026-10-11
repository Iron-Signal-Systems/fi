// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
)

const (
	sorPostgreSQLDatabaseSCRAMIterations = 4096
	sorPostgreSQLDatabaseSCRAMSaltBytes  = 16
)

func generateSORPostgreSQLDatabaseSCRAMVerifier(
	secret string,
	random io.Reader,
) (string, error) {
	if !isSORPostgreSQLDatabaseCredentialSecret(
		secret,
	) {
		return "",
			fmt.Errorf(
				"FI PostgreSQL credential secret is invalid",
			)
	}

	if random == nil {
		random = rand.Reader
	}

	salt :=
		make(
			[]byte,
			sorPostgreSQLDatabaseSCRAMSaltBytes,
		)

	if _, err :=
		io.ReadFull(
			random,
			salt,
		); err != nil {
		return "",
			fmt.Errorf(
				"generate FI PostgreSQL SCRAM salt: %w",
				err,
			)
	}

	saltedPassword :=
		deriveSORPostgreSQLDatabaseSCRAMSHA256(
			[]byte(secret),
			salt,
			sorPostgreSQLDatabaseSCRAMIterations,
		)

	clientMAC :=
		hmac.New(
			sha256.New,
			saltedPassword,
		)

	_, _ =
		clientMAC.Write(
			[]byte("Client Key"),
		)

	clientKey :=
		clientMAC.Sum(nil)

	storedKey :=
		sha256.Sum256(
			clientKey,
		)

	serverMAC :=
		hmac.New(
			sha256.New,
			saltedPassword,
		)

	_, _ =
		serverMAC.Write(
			[]byte("Server Key"),
		)

	serverKey :=
		serverMAC.Sum(nil)

	verifier :=
		fmt.Sprintf(
			"SCRAM-SHA-256$%d:%s$%s:%s",
			sorPostgreSQLDatabaseSCRAMIterations,
			base64.StdEncoding.EncodeToString(
				salt,
			),
			base64.StdEncoding.EncodeToString(
				storedKey[:],
			),
			base64.StdEncoding.EncodeToString(
				serverKey,
			),
		)

	matches, err :=
		verifySORPostgreSQLDatabaseSCRAMSHA256(
			secret,
			verifier,
		)
	if err != nil {
		return "",
			fmt.Errorf(
				"verify generated FI PostgreSQL SCRAM verifier: %w",
				err,
			)
	}

	if !matches {
		return "",
			fmt.Errorf(
				"generated FI PostgreSQL SCRAM verifier does not match credential",
			)
	}

	return verifier, nil
}
