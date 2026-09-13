// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package certstore

import (
	"encoding/hex"
	"errors"
	"strings"
)

func normalizeCertificateSHA256(value string) (string, error) {
	if len(value) != 64 {
		return "", errors.New(
			"certificate SHA-256 must contain exactly 64 hexadecimal characters",
		)
	}

	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		return "", errors.New(
			"certificate SHA-256 must contain exactly 64 hexadecimal characters",
		)
	}

	return strings.ToLower(value), nil
}
