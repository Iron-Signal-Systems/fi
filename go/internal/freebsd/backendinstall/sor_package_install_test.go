// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestAcceptedPostgreSQL18Version(t *testing.T) {
	accepted := []string{
		"18",
		"18.6",
		"18.7",
	}

	for _, version := range accepted {
		if !acceptedPostgreSQL18Version(version) {
			t.Fatalf(
				"acceptedPostgreSQL18Version(%q) = false",
				version,
			)
		}
	}

	if acceptedPostgreSQL18Version("17.6") {
		t.Fatal(
			"acceptedPostgreSQL18Version accepted PostgreSQL 17",
		)
	}
}

func TestInspectSORPostgreSQLAbsent(t *testing.T) {
	root := t.TempDir()
	pgdata := filepath.Join(
		t.TempDir(),
		"postgres",
	)

	if err := os.MkdirAll(
		filepath.Join(
			root,
			"etc",
		),
		0o755,
	); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(
		filepath.Join(
			root,
			"etc/master.passwd",
		),
		[]byte(
			"root:*:0:0::0:0:Charlie &:/root:/bin/csh\n",
		),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(
		filepath.Join(
			root,
			"etc/group",
		),
		[]byte(
			"wheel:*:0:root\n",
		),
		0o644,
	); err != nil {
		t.Fatal(err)
	}

	if err := os.Mkdir(
		pgdata,
		0o755,
	); err != nil {
		t.Fatal(err)
	}

	installed, _, err := inspectSORPostgreSQL(
		root,
		pgdata,
		func(string) (string, error) {
			t.Fatal(
				"version probe called for absent PostgreSQL",
			)

			return "", nil
		},
	)
	if err != nil {
		t.Fatalf(
			"inspectSORPostgreSQL() error = %v",
			err,
		)
	}

	if installed {
		t.Fatal(
			"absent PostgreSQL classified as installed",
		)
	}
}

func TestInspectSORPostgreSQLOwnedMatch(t *testing.T) {
	root := t.TempDir()

	uid := os.Getuid()
	gid := os.Getgid()

	if uid == 0 || gid == 0 {
		t.Skip(
			"test requires non-root UID/GID",
		)
	}

	if err := os.MkdirAll(
		filepath.Join(
			root,
			"etc",
		),
		0o755,
	); err != nil {
		t.Fatal(err)
	}

	passwd := "postgres:*:" +
		strconv.Itoa(uid) +
		":" +
		strconv.Itoa(gid) +
		"::0:0:PostgreSQL Daemon:/var/db/postgres:/bin/sh\n"

	group := "postgres:*:" +
		strconv.Itoa(gid) +
		":\n"

	if err := os.WriteFile(
		filepath.Join(
			root,
			"etc/master.passwd",
		),
		[]byte(passwd),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(
		filepath.Join(
			root,
			"etc/group",
		),
		[]byte(group),
		0o644,
	); err != nil {
		t.Fatal(err)
	}

	files := []string{
		"usr/local/bin/pg_ctl",
		"usr/local/bin/postgres",
		"usr/local/bin/psql",
		"usr/local/etc/rc.d/postgresql",
	}

	for _, relative := range files {
		target := filepath.Join(
			root,
			relative,
		)

		if err := os.MkdirAll(
			filepath.Dir(target),
			0o755,
		); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(
			target,
			[]byte("test"),
			0o755,
		); err != nil {
			t.Fatal(err)
		}
	}

	pgdata := filepath.Join(
		t.TempDir(),
		"postgres",
	)

	if err := os.Mkdir(
		pgdata,
		0o700,
	); err != nil {
		t.Fatal(err)
	}

	if err := os.Chown(
		pgdata,
		uid,
		gid,
	); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(
		pgdata,
		0o700,
	); err != nil {
		t.Fatal(err)
	}

	installed, identity, err := inspectSORPostgreSQL(
		root,
		pgdata,
		func(string) (string, error) {
			return "18.6", nil
		},
	)
	if err != nil {
		t.Fatalf(
			"inspectSORPostgreSQL() error = %v",
			err,
		)
	}

	if !installed {
		t.Fatal(
			"matching PostgreSQL state not classified as installed",
		)
	}

	if identity.UID != uint64(uid) ||
		identity.GID != uint64(gid) {
		t.Fatalf(
			"identity = %d:%d, want %d:%d",
			identity.UID,
			identity.GID,
			uid,
			gid,
		)
	}
}

func TestValidateSORPostgreSQLPackages(t *testing.T) {
	output := `
pkg|2.7.5|ports-mgmt/pkg
postgresql18-client|18.6|databases/postgresql18-client
postgresql18-server|18.6|databases/postgresql18-server
`

	if err := validateSORPostgreSQLPackages(
		output,
	); err != nil {
		t.Fatalf(
			"validateSORPostgreSQLPackages() error = %v",
			err,
		)
	}
}

func TestValidateSORPostgreSQLPackagesRejectsOriginDrift(t *testing.T) {
	output := `
postgresql18-client|18.6|databases/postgresql18-client
postgresql18-server|18.6|unexpected/postgresql18-server
`

	if err := validateSORPostgreSQLPackages(
		output,
	); err == nil {
		t.Fatal(
			"validateSORPostgreSQLPackages accepted origin drift",
		)
	}
}

func TestSystemSORPackageMutatorCommands(t *testing.T) {
	root := filepath.Join(
		t.TempDir(),
		"fi-sor-db",
	)

	commands := make(
		[][]string,
		0,
	)

	mutator := systemSORPackageMutator{
		execute: func(
			executable string,
			args ...string,
		) ([]byte, error) {
			command := append(
				[]string{
					executable,
				},
				args...,
			)

			commands = append(
				commands,
				command,
			)

			if len(args) >= 3 &&
				args[1] == "/usr/local/sbin/pkg" &&
				args[2] == "query" {
				return []byte(
					"postgresql18-client|18.6|databases/postgresql18-client\n" +
						"postgresql18-server|18.6|databases/postgresql18-server\n",
				), nil
			}

			return nil, nil
		},
	}

	if err := mutator.BootstrapPkg(root); err != nil {
		t.Fatalf(
			"BootstrapPkg() error = %v",
			err,
		)
	}

	if err := mutator.UpdateCatalog(root); err != nil {
		t.Fatalf(
			"UpdateCatalog() error = %v",
			err,
		)
	}

	if err := mutator.InstallPostgreSQL(root); err != nil {
		t.Fatalf(
			"InstallPostgreSQL() error = %v",
			err,
		)
	}

	output, err := mutator.QueryPackages(root)
	if err != nil {
		t.Fatalf(
			"QueryPackages() error = %v",
			err,
		)
	}

	if err := validateSORPostgreSQLPackages(
		output,
	); err != nil {
		t.Fatalf(
			"query output error = %v",
			err,
		)
	}

	if len(commands) != 4 {
		t.Fatalf(
			"command count = %d, want 4: %#v",
			len(commands),
			commands,
		)
	}

	bootstrap := commands[0]

	if len(bootstrap) != 7 ||
		bootstrap[0] != "/usr/sbin/chroot" ||
		bootstrap[1] != root ||
		bootstrap[2] != "/usr/bin/env" ||
		bootstrap[3] != "ASSUME_ALWAYS_YES=yes" ||
		bootstrap[4] != "/usr/sbin/pkg" ||
		bootstrap[5] != "bootstrap" ||
		bootstrap[6] != "-y" {
		t.Fatalf(
			"bootstrap command = %#v",
			bootstrap,
		)
	}
}
