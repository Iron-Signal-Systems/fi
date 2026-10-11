// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"bytes"
	"testing"
)

func TestBuildSORPostgreSQLClusterPolicy(
	t *testing.T,
) {
	config := loadTestConfig(t)

	policy, err := buildSORPostgreSQLClusterPolicy(
		config,
	)
	if err != nil {
		t.Fatalf(
			"buildSORPostgreSQLClusterPolicy() error = %v",
			err,
		)
	}

	expectedAuthority := "" +
		"# FI-MANAGED: ironsignal-fi-freebsd-sor-postgresql-cluster-v1\n" +
		"# FI-ROLE: postgresql-cluster-authority\n" +
		"\n" +
		"postgresql_major=\"18\"\n" +
		"initdb_flags=\"--encoding=UTF8 --locale=C --data-checksums\"\n"

	expectedRuntime := "" +
		"# FI-MANAGED: ironsignal-fi-freebsd-sor-postgresql-runtime-v1\n" +
		"# FI-ROLE: postgresql-runtime-policy\n" +
		"\n" +
		"listen_addresses = '10.77.20.22'\n" +
		"port = 5432\n" +
		"password_encryption = 'scram-sha-256'\n" +
		"unix_socket_directories = '/tmp'\n" +
		"unix_socket_group = 'postgres'\n" +
		"unix_socket_permissions = 0770\n"

	expectedHBA := "" +
		"# FI-MANAGED: ironsignal-fi-freebsd-sor-postgresql-hba-v1\n" +
		"# FI-ROLE: postgresql-client-authentication\n" +
		"#\n" +
		"# Initial state:\n" +
		"#   - local PostgreSQL administration only\n" +
		"#   - no remote database clients\n" +
		"#   - no replication / HA\n" +
		"#\n" +
		"# TYPE  DATABASE  USER  ADDRESS  METHOD\n" +
		"local   all       all            peer\n"

	expectedInclude := "" +
		"# FI-MANAGED-BEGIN: ironsignal-fi-freebsd-sor-postgresql-runtime-v1\n" +
		"include = 'fi-postgresql.conf'\n" +
		"# FI-MANAGED-END: ironsignal-fi-freebsd-sor-postgresql-runtime-v1\n"

	if !bytes.Equal(
		policy.AuthorityContent,
		[]byte(expectedAuthority),
	) {
		t.Fatalf(
			"authority content differs:\n%q",
			policy.AuthorityContent,
		)
	}

	if !bytes.Equal(
		policy.RuntimeContent,
		[]byte(expectedRuntime),
	) {
		t.Fatalf(
			"runtime content differs:\n%q",
			policy.RuntimeContent,
		)
	}

	if !bytes.Equal(
		policy.HBAContent,
		[]byte(expectedHBA),
	) {
		t.Fatalf(
			"HBA content differs:\n%q",
			policy.HBAContent,
		)
	}

	if !bytes.Equal(
		policy.IncludeBlock,
		[]byte(expectedInclude),
	) {
		t.Fatalf(
			"include block differs:\n%q",
			policy.IncludeBlock,
		)
	}

	expectedPaths := map[string]string{
		"authority": "/var/db/fi/sor/postgres/.fi-cluster",
		"runtime":   "/var/db/fi/sor/postgres/fi-postgresql.conf",
		"hba":       "/var/db/fi/sor/postgres/pg_hba.conf",
		"main":      "/var/db/fi/sor/postgres/postgresql.conf",
	}

	actualPaths := map[string]string{
		"authority": policy.AuthorityPath,
		"runtime":   policy.RuntimePath,
		"hba":       policy.HBAPath,
		"main":      policy.MainConfigPath,
	}

	for name, expected := range expectedPaths {
		if actualPaths[name] != expected {
			t.Fatalf(
				"%s path = %q, want %q",
				name,
				actualPaths[name],
				expected,
			)
		}
	}
}

func TestSORPostgreSQLWorkAddressCIDR(
	t *testing.T,
) {
	actual, err := sorPostgreSQLWorkAddress(
		"10.77.20.22/24",
	)
	if err != nil {
		t.Fatalf(
			"sorPostgreSQLWorkAddress() error = %v",
			err,
		)
	}

	if actual != "10.77.20.22" {
		t.Fatalf(
			"address = %q, want 10.77.20.22",
			actual,
		)
	}
}

func TestSORPostgreSQLWorkAddressPlain(
	t *testing.T,
) {
	actual, err := sorPostgreSQLWorkAddress(
		"10.77.20.22",
	)
	if err != nil {
		t.Fatalf(
			"sorPostgreSQLWorkAddress() error = %v",
			err,
		)
	}

	if actual != "10.77.20.22" {
		t.Fatalf(
			"address = %q, want 10.77.20.22",
			actual,
		)
	}
}

func TestSORPostgreSQLWorkAddressRejectsInvalid(
	t *testing.T,
) {
	if _, err := sorPostgreSQLWorkAddress(
		"not-an-address",
	); err == nil {
		t.Fatal(
			"sorPostgreSQLWorkAddress accepted invalid address",
		)
	}
}
