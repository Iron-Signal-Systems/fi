// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"fmt"
	"net/netip"
	"path/filepath"
)

const (
	sorPostgreSQLClusterMajorVersion = "18"

	sorPostgreSQLClusterAuthorityMarker = "# FI-MANAGED: ironsignal-fi-freebsd-sor-postgresql-cluster-v1"

	sorPostgreSQLClusterAuthorityRole = "# FI-ROLE: postgresql-cluster-authority"

	sorPostgreSQLRuntimePolicyMarker = "# FI-MANAGED: ironsignal-fi-freebsd-sor-postgresql-runtime-v1"

	sorPostgreSQLRuntimePolicyRole = "# FI-ROLE: postgresql-runtime-policy"

	sorPostgreSQLHBAMarker = "# FI-MANAGED: ironsignal-fi-freebsd-sor-postgresql-hba-v1"

	sorPostgreSQLHBARole = "# FI-ROLE: postgresql-client-authentication"

	sorPostgreSQLIncludeBegin = "# FI-MANAGED-BEGIN: ironsignal-fi-freebsd-sor-postgresql-runtime-v1"

	sorPostgreSQLIncludeLine = "include = 'fi-postgresql.conf'"

	sorPostgreSQLIncludeEnd = "# FI-MANAGED-END: ironsignal-fi-freebsd-sor-postgresql-runtime-v1"
)

type sorPostgreSQLClusterPolicy struct {
	AuthorityContent        []byte
	AuthorityPath           string
	HBAContent              []byte
	HBADatabaseReadyContent []byte
	HBAPath                 string
	IncludeBlock            []byte
	MainConfigPath          string
	RuntimeContent          []byte
	RuntimePath             string
}

func buildSORPostgreSQLClusterPolicy(
	config Config,
) (sorPostgreSQLClusterPolicy, error) {
	workAddress, err := sorPostgreSQLWorkAddress(
		config.Value("FI_SOR_DB_WORK_ADDRESS"),
	)
	if err != nil {
		return sorPostgreSQLClusterPolicy{}, err
	}

	ingestWorkAddress, err := sorPostgreSQLWorkAddress(
		config.Value("FI_INGEST_WORK_ADDRESS"),
	)
	if err != nil {
		return sorPostgreSQLClusterPolicy{}, fmt.Errorf(
			"invalid FI ingest workload address for PostgreSQL HBA: %w",
			err,
		)
	}

	pgdata := config.Value(
		"FI_SOR_POSTGRES_HOST",
	)

	authorityContent := []byte(
		sorPostgreSQLClusterAuthorityMarker + "\n" +
			sorPostgreSQLClusterAuthorityRole + "\n" +
			"\n" +
			"postgresql_major=\"18\"\n" +
			"initdb_flags=\"--encoding=UTF8 --locale=C --data-checksums\"\n",
	)

	runtimeContent := []byte(
		sorPostgreSQLRuntimePolicyMarker + "\n" +
			sorPostgreSQLRuntimePolicyRole + "\n" +
			"\n" +
			"listen_addresses = '" + workAddress + "'\n" +
			"port = 5432\n" +
			"password_encryption = 'scram-sha-256'\n" +
			"unix_socket_directories = '/tmp'\n" +
			"unix_socket_group = 'postgres'\n" +
			"unix_socket_permissions = 0770\n",
	)

	hbaContent := []byte(
		sorPostgreSQLHBAMarker + "\n" +
			sorPostgreSQLHBARole + "\n" +
			"#\n" +
			"# Initial state:\n" +
			"#   - local PostgreSQL administration only\n" +
			"#   - no remote database clients\n" +
			"#   - no replication / HA\n" +
			"#\n" +
			"# TYPE  DATABASE  USER  ADDRESS  METHOD\n" +
			"local   all       all            peer\n",
	)

	hbaDatabaseReadyContent := []byte(
		sorPostgreSQLHBAMarker + "\n" +
			sorPostgreSQLHBARole + "\n" +
			"#\n" +
			"# Database-ready state:\n" +
			"#   - local PostgreSQL administration\n" +
			"#   - FI ingest runtime only\n" +
			"#   - no replication / HA\n" +
			"#\n" +
			"# TYPE  DATABASE  USER       ADDRESS  METHOD\n" +
			"local   all       all                 peer\n" +
			"host    fi        fi_ingest  " +
			ingestWorkAddress +
			"/32  scram-sha-256\n",
	)

	includeBlock := []byte(
		sorPostgreSQLIncludeBegin + "\n" +
			sorPostgreSQLIncludeLine + "\n" +
			sorPostgreSQLIncludeEnd + "\n",
	)

	return sorPostgreSQLClusterPolicy{
		AuthorityContent: authorityContent,
		AuthorityPath: filepath.Join(
			pgdata,
			".fi-cluster",
		),
		HBAContent:              hbaContent,
		HBADatabaseReadyContent: hbaDatabaseReadyContent,
		HBAPath: filepath.Join(
			pgdata,
			"pg_hba.conf",
		),
		IncludeBlock: includeBlock,
		MainConfigPath: filepath.Join(
			pgdata,
			"postgresql.conf",
		),
		RuntimeContent: runtimeContent,
		RuntimePath: filepath.Join(
			pgdata,
			"fi-postgresql.conf",
		),
	}, nil
}

func sorPostgreSQLWorkAddress(
	value string,
) (string, error) {
	prefix, err := netip.ParsePrefix(value)
	if err == nil {
		return prefix.Addr().String(), nil
	}

	address, addressErr := netip.ParseAddr(value)
	if addressErr == nil {
		return address.String(), nil
	}

	return "", fmt.Errorf(
		"invalid System-of-Record PostgreSQL workload address: %q",
		value,
	)
}
