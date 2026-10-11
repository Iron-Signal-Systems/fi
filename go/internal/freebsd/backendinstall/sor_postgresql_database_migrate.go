// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

func applySORPostgreSQLDatabaseMigrations(
	policy sorPostgreSQLDatabasePolicy,
	assets []sorPostgreSQLDatabaseMigrationAsset,
	execute func(
		string,
		string,
		[]byte,
	) error,
) error {
	if policy.DatabaseName == "" {
		return fmt.Errorf(
			"PostgreSQL migration database is required",
		)
	}

	if execute == nil {
		return fmt.Errorf(
			"PostgreSQL migration executor is required",
		)
	}

	if policy.OwnerRole.Name == "" {
		return fmt.Errorf(
			"PostgreSQL migration owner role is required",
		)
	}

	if len(policy.Migrations) == 0 {
		return fmt.Errorf(
			"PostgreSQL migration policy is empty",
		)
	}

	if len(assets) !=
		len(policy.Migrations) {
		return fmt.Errorf(
			"PostgreSQL migration asset count = %d, want %d",
			len(assets),
			len(policy.Migrations),
		)
	}

	for index := range policy.Migrations {
		expected :=
			policy.Migrations[index]

		asset :=
			assets[index]

		if expected.Name == "" {
			return fmt.Errorf(
				"PostgreSQL migration policy %d has empty name",
				index,
			)
		}

		if expected.SHA256 == "" {
			return fmt.Errorf(
				"PostgreSQL migration policy %s has empty SHA256",
				expected.Name,
			)
		}

		if asset.Name !=
			expected.Name {
			return fmt.Errorf(
				"PostgreSQL migration asset %d name = %q, want %q",
				index,
				asset.Name,
				expected.Name,
			)
		}

		if asset.SHA256 !=
			expected.SHA256 {
			return fmt.Errorf(
				"PostgreSQL migration %s declared SHA256 = %q, want %q",
				asset.Name,
				asset.SHA256,
				expected.SHA256,
			)
		}

		if strings.TrimSpace(
			asset.SQL,
		) == "" {
			return fmt.Errorf(
				"PostgreSQL migration %s SQL is empty",
				asset.Name,
			)
		}

		digest :=
			sha256.Sum256(
				[]byte(
					asset.SQL,
				),
			)

		actual :=
			hex.EncodeToString(
				digest[:],
			)

		if actual !=
			expected.SHA256 {
			return fmt.Errorf(
				"PostgreSQL migration %s embedded SHA256 = %q, want %q",
				asset.Name,
				actual,
				expected.SHA256,
			)
		}

		if err :=
			execute(
				policy.DatabaseName,
				policy.OwnerRole.Name,
				[]byte(
					asset.SQL,
				),
			); err != nil {
			return fmt.Errorf(
				"apply PostgreSQL migration %s: %w",
				asset.Name,
				err,
			)
		}
	}

	return nil
}
