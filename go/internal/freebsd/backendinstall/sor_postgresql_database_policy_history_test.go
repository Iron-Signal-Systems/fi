// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import "testing"

func TestSORPostgreSQLDatabasePolicyHistoricalRoleAttributes(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	if !policy.OwnerRole.Inherit {
		t.Fatal(
			"fi_owner policy must preserve PostgreSQL INHERIT",
		)
	}

	if !policy.IngestRole.Inherit {
		t.Fatal(
			"fi_ingest policy must preserve PostgreSQL INHERIT",
		)
	}

	if policy.OwnerRole.CanLogin {
		t.Fatal(
			"fi_owner must remain NOLOGIN",
		)
	}

	if !policy.IngestRole.CanLogin {
		t.Fatal(
			"fi_ingest must remain LOGIN",
		)
	}
}

func TestSORPostgreSQLDatabasePolicyHistoricalDatabaseLocale(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	if policy.DatabaseEncoding !=
		"UTF8" {
		t.Fatalf(
			"database encoding = %q, want UTF8",
			policy.DatabaseEncoding,
		)
	}

	if policy.DatabaseCollate !=
		"C.UTF-8" {
		t.Fatalf(
			"database collate = %q, want C.UTF-8",
			policy.DatabaseCollate,
		)
	}

	if policy.DatabaseCType !=
		"C.UTF-8" {
		t.Fatalf(
			"database ctype = %q, want C.UTF-8",
			policy.DatabaseCType,
		)
	}
}
