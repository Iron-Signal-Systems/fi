// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportcrl

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/Iron-Signal-Systems/fi/go/internal/receivertrust"
)

func EncodeCanonicalPEM(
	der []byte,
) ([]byte, error) {
	if len(der) == 0 {
		return nil, errors.New(
			"transport CRL DER is empty",
		)
	}

	encoded := pem.EncodeToMemory(
		&pem.Block{
			Type:  "X509 CRL",
			Bytes: der,
		},
	)

	if len(encoded) == 0 {
		return nil, errors.New(
			"encode canonical transport CRL PEM returned no data",
		)
	}

	return encoded, nil
}

func VerifyPersistedPEM(
	path string,
	expectedDER []byte,
	expectedSHA256 string,
) error {
	if len(expectedDER) == 0 {
		return errors.New(
			"expected transport CRL DER is empty",
		)
	}

	if len(expectedSHA256) != 64 {
		return errors.New(
			"expected transport CRL SHA-256 must contain exactly 64 hexadecimal characters",
		)
	}

	value, err := receivertrust.LoadCRL(
		path,
	)
	if err != nil {
		return fmt.Errorf(
			"verify persisted transport CRL %s: %w",
			path,
			err,
		)
	}

	if !bytes.Equal(
		value.Raw,
		expectedDER,
	) {
		return fmt.Errorf(
			"persisted transport CRL %s does not reproduce the expected DER",
			path,
		)
	}

	digest := sha256.Sum256(
		value.Raw,
	)

	observed := hex.EncodeToString(
		digest[:],
	)

	if !stringsEqualFoldASCII(
		observed,
		expectedSHA256,
	) {
		return fmt.Errorf(
			"persisted transport CRL SHA256=%s does not match expected SHA256=%s",
			observed,
			expectedSHA256,
		)
	}

	return nil
}

func stringsEqualFoldASCII(
	left string,
	right string,
) bool {
	if len(left) != len(right) {
		return false
	}

	for index := range left {
		a := left[index]
		b := right[index]

		if a >= 'A' && a <= 'Z' {
			a += 'a' - 'A'
		}

		if b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}

		if a != b {
			return false
		}
	}

	return true
}
