// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"os"
	"path/filepath"
	"testing"
)

func TestClassifySORPostgreSQLClusterPolicyUnmanaged(
	t *testing.T,
) {
	root, uid, gid := testSORPostgreSQLInitializedRoot(
		t,
	)

	policy := testSORPostgreSQLClusterPolicy(
		t,
		root,
	)

	state := classifySORPostgreSQLClusterPolicy(
		policy,
		uid,
		gid,
	)

	if state != sorPostgreSQLClusterPolicyUnmanaged {
		t.Fatalf(
			"state = %s, want UNMANAGED",
			state,
		)
	}
}

func TestClassifySORPostgreSQLClusterPolicyOwnedMatch(
	t *testing.T,
) {
	root, uid, gid := testSORPostgreSQLInitializedRoot(
		t,
	)

	policy := testSORPostgreSQLClusterPolicy(
		t,
		root,
	)

	writeTestSORPostgreSQLManagedClusterPolicy(
		t,
		policy,
	)

	state := classifySORPostgreSQLClusterPolicy(
		policy,
		uid,
		gid,
	)

	if state != sorPostgreSQLClusterPolicyOwnedMatch {
		t.Fatalf(
			"state = %s, want OWNED_MATCH",
			state,
		)
	}
}

func TestClassifySORPostgreSQLClusterPolicyRejectsMixedState(
	t *testing.T,
) {
	root, uid, gid := testSORPostgreSQLInitializedRoot(
		t,
	)

	policy := testSORPostgreSQLClusterPolicy(
		t,
		root,
	)

	writeTestSORPostgreSQLPolicyFile(
		t,
		policy.AuthorityPath,
		policy.AuthorityContent,
	)

	state := classifySORPostgreSQLClusterPolicy(
		policy,
		uid,
		gid,
	)

	if state != sorPostgreSQLClusterPolicyOwnedDrift {
		t.Fatalf(
			"state = %s, want OWNED_DRIFT",
			state,
		)
	}
}

func TestClassifySORPostgreSQLClusterPolicyRejectsForeignRuntime(
	t *testing.T,
) {
	root, uid, gid := testSORPostgreSQLInitializedRoot(
		t,
	)

	policy := testSORPostgreSQLClusterPolicy(
		t,
		root,
	)

	writeTestSORPostgreSQLPolicyFile(
		t,
		policy.RuntimePath,
		[]byte(
			"listen_addresses = '127.0.0.1'\n",
		),
	)

	state := classifySORPostgreSQLClusterPolicy(
		policy,
		uid,
		gid,
	)

	if state !=
		sorPostgreSQLClusterPolicyForeignCollision {
		t.Fatalf(
			"state = %s, want FOREIGN_COLLISION",
			state,
		)
	}
}

func TestClassifySORPostgreSQLClusterPolicyRejectsHBADrift(
	t *testing.T,
) {
	root, uid, gid := testSORPostgreSQLInitializedRoot(
		t,
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
		policy.HBAPath,
		os.O_APPEND|os.O_WRONLY,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := file.WriteString(
		"host all all 0.0.0.0/0 trust\n",
	); err != nil {
		file.Close()
		t.Fatal(err)
	}

	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	state := classifySORPostgreSQLClusterPolicy(
		policy,
		uid,
		gid,
	)

	if state != sorPostgreSQLClusterPolicyOwnedDrift {
		t.Fatalf(
			"state = %s, want OWNED_DRIFT",
			state,
		)
	}
}

func TestClassifySORPostgreSQLClusterPolicyRejectsDuplicateInclude(
	t *testing.T,
) {
	root, uid, gid := testSORPostgreSQLInitializedRoot(
		t,
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
		policy.MainConfigPath,
		os.O_APPEND|os.O_WRONLY,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := file.Write(
		policy.IncludeBlock,
	); err != nil {
		file.Close()
		t.Fatal(err)
	}

	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	state := classifySORPostgreSQLClusterPolicy(
		policy,
		uid,
		gid,
	)

	if state != sorPostgreSQLClusterPolicyOwnedDrift {
		t.Fatalf(
			"state = %s, want OWNED_DRIFT",
			state,
		)
	}
}

func TestClassifySORPostgreSQLClusterPolicyRejectsForeignInclude(
	t *testing.T,
) {
	root, uid, gid := testSORPostgreSQLInitializedRoot(
		t,
	)

	policy := testSORPostgreSQLClusterPolicy(
		t,
		root,
	)

	file, err := os.OpenFile(
		policy.MainConfigPath,
		os.O_APPEND|os.O_WRONLY,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := file.WriteString(
		"include = 'fi-postgresql.conf'\n",
	); err != nil {
		file.Close()
		t.Fatal(err)
	}

	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	state := classifySORPostgreSQLClusterPolicy(
		policy,
		uid,
		gid,
	)

	if state !=
		sorPostgreSQLClusterPolicyForeignCollision {
		t.Fatalf(
			"state = %s, want FOREIGN_COLLISION",
			state,
		)
	}
}

func testSORPostgreSQLInitializedRoot(
	t *testing.T,
) (string, uint64, uint64) {
	t.Helper()

	root := t.TempDir()

	if err := os.Chown(
		root,
		os.Geteuid(),
		os.Getegid(),
	); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(
		root,
		0o700,
	); err != nil {
		t.Fatal(err)
	}

	writeTestSORPostgreSQLCluster(
		t,
		root,
	)

	return root,
		uint64(os.Geteuid()),
		uint64(os.Getegid())
}

func testSORPostgreSQLClusterPolicy(
	t *testing.T,
	root string,
) sorPostgreSQLClusterPolicy {
	t.Helper()

	policy, err := buildSORPostgreSQLClusterPolicy(
		loadTestConfig(t),
	)
	if err != nil {
		t.Fatal(err)
	}

	policy.AuthorityPath = filepath.Join(
		root,
		".fi-cluster",
	)

	policy.RuntimePath = filepath.Join(
		root,
		"fi-postgresql.conf",
	)

	policy.HBAPath = filepath.Join(
		root,
		"pg_hba.conf",
	)

	policy.MainConfigPath = filepath.Join(
		root,
		"postgresql.conf",
	)

	return policy
}

func writeTestSORPostgreSQLManagedClusterPolicy(
	t *testing.T,
	policy sorPostgreSQLClusterPolicy,
) {
	t.Helper()

	writeTestSORPostgreSQLPolicyFile(
		t,
		policy.AuthorityPath,
		policy.AuthorityContent,
	)

	writeTestSORPostgreSQLPolicyFile(
		t,
		policy.RuntimePath,
		policy.RuntimeContent,
	)

	writeTestSORPostgreSQLPolicyFile(
		t,
		policy.HBAPath,
		policy.HBAContent,
	)

	content, err := os.ReadFile(
		policy.MainConfigPath,
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(content) > 0 &&
		content[len(content)-1] != '\n' {
		content = append(
			content,
			'\n',
		)
	}

	content = append(
		content,
		policy.IncludeBlock...,
	)

	if err := os.WriteFile(
		policy.MainConfigPath,
		content,
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(
		policy.MainConfigPath,
		0o600,
	); err != nil {
		t.Fatal(err)
	}
}

func writeTestSORPostgreSQLPolicyFile(
	t *testing.T,
	target string,
	content []byte,
) {
	t.Helper()

	if err := os.WriteFile(
		target,
		content,
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
