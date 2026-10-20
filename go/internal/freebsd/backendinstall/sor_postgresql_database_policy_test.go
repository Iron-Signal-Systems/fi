// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"strings"
	"testing"
)

func TestSORPostgreSQLDatabasePolicyIdentity(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	if policy.DatabaseName != "fi" {
		t.Fatalf(
			"database = %q, want fi",
			policy.DatabaseName,
		)
	}

	if policy.DatabaseOwner != "fi_owner" {
		t.Fatalf(
			"database owner = %q, want fi_owner",
			policy.DatabaseOwner,
		)
	}

	if policy.SchemaName != "fi" {
		t.Fatalf(
			"schema = %q, want fi",
			policy.SchemaName,
		)
	}

	if policy.SchemaOwner != "fi_owner" {
		t.Fatalf(
			"schema owner = %q, want fi_owner",
			policy.SchemaOwner,
		)
	}

	if policy.OwnerRole.Name != "fi_owner" {
		t.Fatalf(
			"owner role = %q, want fi_owner",
			policy.OwnerRole.Name,
		)
	}

	if policy.IngestRole.Name != "fi_ingest" {
		t.Fatalf(
			"ingest role = %q, want fi_ingest",
			policy.IngestRole.Name,
		)
	}
}

func TestSORPostgreSQLDatabasePolicyRoleRestrictions(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	owner := policy.OwnerRole

	if owner.CanLogin ||
		owner.Superuser ||
		owner.CreateRole ||
		owner.CreateDB ||
		owner.Replication ||
		owner.BypassRLS ||
		owner.PasswordRequired {
		t.Fatalf(
			"fi_owner role policy is not restricted: %+v",
			owner,
		)
	}

	ingest := policy.IngestRole

	if !ingest.CanLogin {
		t.Fatal(
			"fi_ingest must be LOGIN",
		)
	}

	if ingest.Superuser ||
		ingest.CreateRole ||
		ingest.CreateDB ||
		ingest.Replication ||
		ingest.BypassRLS {
		t.Fatalf(
			"fi_ingest role policy is over-privileged: %+v",
			ingest,
		)
	}

	if !ingest.PasswordRequired {
		t.Fatal(
			"fi_ingest must require a credential",
		)
	}
}

func TestSORPostgreSQLDatabasePolicyAuthorityComments(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	values := []struct {
		Name    string
		Content string
		Role    string
	}{
		{
			Name:    "owner-role",
			Content: policy.OwnerRole.Comment,
			Role:    "FI-ROLE: database-owner",
		},
		{
			Name:    "ingest-role",
			Content: policy.IngestRole.Comment,
			Role:    "FI-ROLE: database-ingest",
		},
		{
			Name:    "database",
			Content: policy.DatabaseComment,
			Role:    "FI-ROLE: authoritative-database",
		},
		{
			Name:    "schema",
			Content: policy.SchemaComment,
			Role:    "FI-ROLE: relational-schema",
		},
	}

	for _, value := range values {
		if !strings.Contains(
			value.Content,
			sorPostgreSQLDatabaseAuthorityMarker,
		) {
			t.Fatalf(
				"%s missing authority marker",
				value.Name,
			)
		}

		if !strings.Contains(
			value.Content,
			value.Role,
		) {
			t.Fatalf(
				"%s missing role marker",
				value.Name,
			)
		}
	}

	for _, expected := range []string{
		sorPostgreSQLDatabaseMigration0001SHA256,
		sorPostgreSQLDatabaseMigration0002SHA256,
		sorPostgreSQLDatabaseMigration0003SHA256,
	} {
		if !strings.Contains(
			policy.SchemaComment,
			expected,
		) {
			t.Fatalf(
				"schema authority missing migration hash %s",
				expected,
			)
		}
	}
}

func TestSORPostgreSQLDatabasePolicyMigrationContract(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	expected := []struct {
		Name   string
		SHA256 string
	}{
		{
			Name:   "0001_relational.sql",
			SHA256: "f83ffb7754e22eef6230300b38ff6d1cf039791fd08f356c77efa2e30b462ebf",
		},
		{
			Name:   "0002_source_families.sql",
			SHA256: "82050818f1424b7870a1b992b182abeb5497fe52c5a6f84d08fdefc76c496439",
		},
		{
			Name:   "0003_usn_relational_identity.sql",
			SHA256: "906dccf64eaf13a0a008bc870801beefb2d372f71574d10fe40ae5f1ba5a174c",
		},
		{
			Name:   "0004_security_field_name_index.sql",
			SHA256: "9a2a54875828e82eed9dbbb36ddaa0b6886bdc43789f1a220f41bf40cd1460dc",
		},
	}

	if len(policy.Migrations) != len(expected) {
		t.Fatalf(
			"migration count = %d, want %d",
			len(policy.Migrations),
			len(expected),
		)
	}

	for index := range expected {
		if policy.Migrations[index].Name !=
			expected[index].Name {
			t.Fatalf(
				"migration %d name = %q, want %q",
				index,
				policy.Migrations[index].Name,
				expected[index].Name,
			)
		}

		if policy.Migrations[index].SHA256 !=
			expected[index].SHA256 {
			t.Fatalf(
				"migration %d SHA = %q, want %q",
				index,
				policy.Migrations[index].SHA256,
				expected[index].SHA256,
			)
		}
	}
}

func TestSORPostgreSQLDatabasePolicyRuntimeEndpoint(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	if policy.SORWorkAddress !=
		"10.77.20.22" {
		t.Fatalf(
			"SOR address = %q, want 10.77.20.22",
			policy.SORWorkAddress,
		)
	}

	if policy.IngestWorkAddress !=
		"10.77.20.21" {
		t.Fatalf(
			"ingest address = %q, want 10.77.20.21",
			policy.IngestWorkAddress,
		)
	}

	expectedPrefix :=
		"10.77.20.22:5432:fi:fi_ingest:"

	if policy.PassfilePrefix !=
		expectedPrefix {
		t.Fatalf(
			"passfile prefix = %q, want %q",
			policy.PassfilePrefix,
			expectedPrefix,
		)
	}

	expectedPath :=
		"/var/db/fi/config/ingest/postgres.pgpass"

	if policy.PassfilePath !=
		expectedPath {
		t.Fatalf(
			"passfile path = %q, want %q",
			policy.PassfilePath,
			expectedPath,
		)
	}
}

func TestSORPostgreSQLDatabasePolicyRelationalFoundation(
	t *testing.T,
) {
	policy :=
		testSORPostgreSQLDatabasePolicy(
			t,
		)

	if policy.ExpectedRelationalTableCount !=
		49 {
		t.Fatalf(
			"relational table count = %d, want 49",
			policy.ExpectedRelationalTableCount,
		)
	}

	expectedCore := []string{
		"recorded_generation",
		"source_batch",
		"source_record",
		"ingest_journal",
		"ntfs_volume",
		"ntfs_object",
		"governed_root",
		"file_observation",
		"usn_read_boundary",
		"usn_object_observation",
		"usn_object_change",
		"windows_security_event",
	}

	if len(policy.CoreTables) !=
		len(expectedCore) {
		t.Fatalf(
			"core table count = %d, want %d",
			len(policy.CoreTables),
			len(expectedCore),
		)
	}

	for index := range expectedCore {
		if policy.CoreTables[index] !=
			expectedCore[index] {
			t.Fatalf(
				"core table %d = %q, want %q",
				index,
				policy.CoreTables[index],
				expectedCore[index],
			)
		}
	}
}

func testSORPostgreSQLDatabasePolicy(
	t *testing.T,
) sorPostgreSQLDatabasePolicy {
	t.Helper()

	policy, err :=
		buildSORPostgreSQLDatabasePolicy(
			loadTestConfig(t),
		)
	if err != nil {
		t.Fatalf(
			"buildSORPostgreSQLDatabasePolicy() error = %v",
			err,
		)
	}

	return policy
}
