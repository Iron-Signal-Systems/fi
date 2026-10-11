// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestClassifySORPostgreSQLClusterAbsent(
	t *testing.T,
) {
	spec := testSORPostgreSQLClusterSpec(
		filepath.Join(
			t.TempDir(),
			"absent",
		),
	)

	state := classifySORPostgreSQLCluster(spec)

	if state != sorPostgreSQLClusterAbsent {
		t.Fatalf(
			"state = %s, want ABSENT",
			state,
		)
	}
}

func TestClassifySORPostgreSQLClusterEmpty(
	t *testing.T,
) {
	root := t.TempDir()

	if err := os.Chmod(
		root,
		0o700,
	); err != nil {
		t.Fatal(err)
	}

	spec := testSORPostgreSQLClusterSpec(root)

	state := classifySORPostgreSQLCluster(spec)

	if state != sorPostgreSQLClusterEmpty {
		t.Fatalf(
			"state = %s, want EMPTY",
			state,
		)
	}
}

func TestClassifySORPostgreSQLClusterInitialized(
	t *testing.T,
) {
	root := t.TempDir()

	writeTestSORPostgreSQLCluster(
		t,
		root,
	)

	spec := testSORPostgreSQLClusterSpec(root)

	state := classifySORPostgreSQLCluster(spec)

	if state != sorPostgreSQLClusterInitialized {
		t.Fatalf(
			"state = %s, want INITIALIZED",
			state,
		)
	}
}

func TestClassifySORPostgreSQLClusterRejectsPartial(
	t *testing.T,
) {
	root := t.TempDir()

	if err := os.Chmod(
		root,
		0o700,
	); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(
		filepath.Join(
			root,
			"unexpected",
		),
		[]byte("partial\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	spec := testSORPostgreSQLClusterSpec(root)

	state := classifySORPostgreSQLCluster(spec)

	if state != sorPostgreSQLClusterPartial {
		t.Fatalf(
			"state = %s, want PARTIAL",
			state,
		)
	}
}

func TestClassifySORPostgreSQLClusterRejectsVersionDrift(
	t *testing.T,
) {
	root := t.TempDir()

	writeTestSORPostgreSQLCluster(
		t,
		root,
	)

	if err := os.WriteFile(
		filepath.Join(
			root,
			"PG_VERSION",
		),
		[]byte("17\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	spec := testSORPostgreSQLClusterSpec(root)

	state := classifySORPostgreSQLCluster(spec)

	if state != sorPostgreSQLClusterPartial {
		t.Fatalf(
			"state = %s, want PARTIAL",
			state,
		)
	}
}

func TestClassifySORPostgreSQLClusterRejectsPostmasterPID(
	t *testing.T,
) {
	root := t.TempDir()

	writeTestSORPostgreSQLCluster(
		t,
		root,
	)

	if err := os.WriteFile(
		filepath.Join(
			root,
			"postmaster.pid",
		),
		[]byte("1234\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	spec := testSORPostgreSQLClusterSpec(root)

	state := classifySORPostgreSQLCluster(spec)

	if state != sorPostgreSQLClusterPartial {
		t.Fatalf(
			"state = %s, want PARTIAL",
			state,
		)
	}
}

func TestClassifySORPostgreSQLClusterRejectsSymlink(
	t *testing.T,
) {
	root := t.TempDir()

	writeTestSORPostgreSQLCluster(
		t,
		root,
	)

	target := filepath.Join(
		root,
		"PG_VERSION",
	)

	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(
		"/tmp/foreign-pg-version",
		target,
	); err != nil {
		t.Fatal(err)
	}

	spec := testSORPostgreSQLClusterSpec(root)

	state := classifySORPostgreSQLCluster(spec)

	if state != sorPostgreSQLClusterPartial {
		t.Fatalf(
			"state = %s, want PARTIAL",
			state,
		)
	}
}

func testSORPostgreSQLClusterSpec(
	pgdata string,
) sorPostgreSQLClusterSpec {
	authorityPath := pgdata

	info, err := os.Lstat(authorityPath)
	if os.IsNotExist(err) {
		authorityPath = filepath.Dir(pgdata)

		info, err = os.Lstat(authorityPath)
	}

	if err != nil {
		panic(err)
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		panic("test PGDATA authority does not expose syscall.Stat_t")
	}

	return sorPostgreSQLClusterSpec{
		GID:          uint64(stat.Gid),
		MajorVersion: "18",
		PGData:       pgdata,
		UID:          uint64(stat.Uid),
	}
}

func writeTestSORPostgreSQLCluster(
	t *testing.T,
	root string,
) {
	t.Helper()

	if err := os.Chmod(
		root,
		0o700,
	); err != nil {
		t.Fatal(err)
	}

	for _, relative := range []string{
		"base",
		"global",
		"pg_wal",
	} {
		target := filepath.Join(
			root,
			relative,
		)

		if err := os.MkdirAll(
			target,
			0o700,
		); err != nil {
			t.Fatal(err)
		}

		if err := os.Chmod(
			target,
			0o700,
		); err != nil {
			t.Fatal(err)
		}
	}

	files := map[string]string{
		"PG_VERSION":        "18\n",
		"postgresql.conf":   "# generated\n",
		"pg_hba.conf":       "# generated\n",
		"pg_ident.conf":     "# generated\n",
		"global/pg_control": "control\n",
	}

	for relative, content := range files {
		target := filepath.Join(
			root,
			relative,
		)

		if err := os.WriteFile(
			target,
			[]byte(content),
			0o600,
		); err != nil {
			t.Fatal(err)
		}

		if err := os.Chmod(
			target,
			0o600,
		); err != nil {
			t.Fatal(err)
		}
	}
}
