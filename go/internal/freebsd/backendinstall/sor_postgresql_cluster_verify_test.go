// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifySORPostgreSQLClusterStateOwnedMatch(
	t *testing.T,
) {
	root, uid, gid :=
		testSORPostgreSQLInitializedRoot(
			t,
		)

	spec := testSORPostgreSQLClusterSpec(
		root,
	)

	if spec.UID != uid ||
		spec.GID != gid {
		t.Fatalf(
			"fixture identity mismatch: spec=%d:%d fixture=%d:%d",
			spec.UID,
			spec.GID,
			uid,
			gid,
		)
	}

	policy := testSORPostgreSQLClusterPolicy(
		t,
		root,
	)

	writeTestSORPostgreSQLManagedClusterPolicy(
		t,
		policy,
	)

	if err := verifySORPostgreSQLClusterState(
		spec,
		policy,
	); err != nil {
		t.Fatalf(
			"verifySORPostgreSQLClusterState() error = %v",
			err,
		)
	}
}

func TestVerifySORPostgreSQLClusterStateRejectsEmpty(
	t *testing.T,
) {
	root := t.TempDir()

	if err := os.Chmod(
		root,
		0o700,
	); err != nil {
		t.Fatal(err)
	}

	spec := testSORPostgreSQLClusterSpec(
		root,
	)

	policy := testSORPostgreSQLClusterPolicy(
		t,
		root,
	)

	err := verifySORPostgreSQLClusterState(
		spec,
		policy,
	)

	if err == nil {
		t.Fatal(
			"empty PostgreSQL cluster was accepted",
		)
	}

	if !strings.Contains(
		err.Error(),
		"cluster is not INITIALIZED: EMPTY",
	) {
		t.Fatalf(
			"unexpected error = %v",
			err,
		)
	}
}

func TestVerifySORPostgreSQLClusterStateRejectsPartial(
	t *testing.T,
) {
	root, _, _ :=
		testSORPostgreSQLInitializedRoot(
			t,
		)

	spec := testSORPostgreSQLClusterSpec(
		root,
	)

	policy := testSORPostgreSQLClusterPolicy(
		t,
		root,
	)

	if err := os.WriteFile(
		filepath.Join(
			root,
			"postmaster.pid",
		),
		[]byte(
			"1234\n",
		),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	err := verifySORPostgreSQLClusterState(
		spec,
		policy,
	)

	if err == nil {
		t.Fatal(
			"cluster with postmaster.pid was accepted",
		)
	}

	if !strings.Contains(
		err.Error(),
		"cluster is not INITIALIZED: PARTIAL",
	) {
		t.Fatalf(
			"unexpected error = %v",
			err,
		)
	}
}

func TestVerifySORPostgreSQLClusterStateRejectsUnmanagedPolicy(
	t *testing.T,
) {
	root, _, _ :=
		testSORPostgreSQLInitializedRoot(
			t,
		)

	spec := testSORPostgreSQLClusterSpec(
		root,
	)

	policy := testSORPostgreSQLClusterPolicy(
		t,
		root,
	)

	err := verifySORPostgreSQLClusterState(
		spec,
		policy,
	)

	if err == nil {
		t.Fatal(
			"initialized unmanaged cluster was accepted",
		)
	}

	if !strings.Contains(
		err.Error(),
		"cluster policy is not OWNED_MATCH: UNMANAGED",
	) {
		t.Fatalf(
			"unexpected error = %v",
			err,
		)
	}
}

func TestVerifySORPostgreSQLClusterStateRejectsOwnedDrift(
	t *testing.T,
) {
	root, _, _ :=
		testSORPostgreSQLInitializedRoot(
			t,
		)

	spec := testSORPostgreSQLClusterSpec(
		root,
	)

	policy := testSORPostgreSQLClusterPolicy(
		t,
		root,
	)

	writeTestSORPostgreSQLManagedClusterPolicy(
		t,
		policy,
	)

	file, err := os.OpenFile(
		policy.RuntimePath,
		os.O_APPEND|os.O_WRONLY,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := file.WriteString(
		"# drift\n",
	); err != nil {
		file.Close()
		t.Fatal(err)
	}

	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	err = verifySORPostgreSQLClusterState(
		spec,
		policy,
	)

	if err == nil {
		t.Fatal(
			"FI-owned cluster policy drift was accepted",
		)
	}

	if !strings.Contains(
		err.Error(),
		"cluster policy is not OWNED_MATCH: OWNED_DRIFT",
	) {
		t.Fatalf(
			"unexpected error = %v",
			err,
		)
	}
}
