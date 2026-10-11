// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSystemSORPostgreSQLClusterInitializerPublishesPolicy(
	t *testing.T,
) {
	root, uid, gid :=
		testSORPostgreSQLInitializedRoot(
			t,
		)

	policy := testSORPostgreSQLClusterPolicy(
		t,
		root,
	)

	if state :=
		classifySORPostgreSQLClusterPolicy(
			policy,
			uid,
			gid,
		); state != sorPostgreSQLClusterPolicyUnmanaged {
		t.Fatalf(
			"initial policy state = %s, want UNMANAGED",
			state,
		)
	}

	initializer :=
		systemSORPostgreSQLClusterInitializer{}

	if err := initializer.PublishPolicy(
		policy,
		uid,
		gid,
	); err != nil {
		t.Fatalf(
			"PublishPolicy() error = %v",
			err,
		)
	}

	if state :=
		classifySORPostgreSQLClusterPolicy(
			policy,
			uid,
			gid,
		); state != sorPostgreSQLClusterPolicyOwnedMatch {
		t.Fatalf(
			"final policy state = %s, want OWNED_MATCH",
			state,
		)
	}

	mainContent, err := os.ReadFile(
		policy.MainConfigPath,
	)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Count(
		mainContent,
		policy.IncludeBlock,
	) != 1 {
		t.Fatal(
			"postgresql.conf does not contain exactly one FI include block",
		)
	}
}

func TestSystemSORPostgreSQLClusterInitializerPublishPolicyRejectsOwnedMatch(
	t *testing.T,
) {
	root, uid, gid :=
		testSORPostgreSQLInitializedRoot(
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

	initializer :=
		systemSORPostgreSQLClusterInitializer{}

	err := initializer.PublishPolicy(
		policy,
		uid,
		gid,
	)
	if err == nil {
		t.Fatal(
			"PublishPolicy() accepted already-managed policy",
		)
	}

	if !strings.Contains(
		err.Error(),
		"requires exact UNMANAGED state",
	) {
		t.Fatalf(
			"unexpected error = %v",
			err,
		)
	}
}

func TestPublishAbsentSORPostgreSQLPolicyFileNoClobber(
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

	target := filepath.Join(
		root,
		"fi-postgresql.conf",
	)

	expected := []byte(
		"FI expected\n",
	)

	temp, err :=
		stageSORPostgreSQLPolicyFile(
			target,
			expected,
			spec.UID,
			spec.GID,
		)
	if err != nil {
		t.Fatal(err)
	}

	defer removeSORPostgreSQLPolicyTemp(
		temp,
	)

	foreign := []byte(
		"foreign\n",
	)

	if err := os.WriteFile(
		target,
		foreign,
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	err = publishAbsentSORPostgreSQLPolicyFile(
		temp,
		target,
		expected,
		spec.UID,
		spec.GID,
	)
	if err == nil {
		t.Fatal(
			"absent publisher overwrote existing destination",
		)
	}

	actual, err := os.ReadFile(
		target,
	)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(
		actual,
		foreign,
	) {
		t.Fatal(
			"existing destination changed",
		)
	}
}

func TestRequireSORPostgreSQLUnmanagedFileSnapshotRejectsReplacement(
	t *testing.T,
) {
	root, uid, gid :=
		testSORPostgreSQLInitializedRoot(
			t,
		)

	target := filepath.Join(
		root,
		"pg_hba.conf",
	)

	snapshot, err :=
		captureSORPostgreSQLUnmanagedFileSnapshot(
			target,
			uid,
			gid,
		)
	if err != nil {
		t.Fatal(err)
	}

	replacement := filepath.Join(
		root,
		".replacement-pg-hba",
	)

	if err := os.WriteFile(
		replacement,
		snapshot.Content,
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	if err := os.Rename(
		replacement,
		target,
	); err != nil {
		t.Fatal(err)
	}

	err =
		requireSORPostgreSQLUnmanagedFileSnapshot(
			snapshot,
		)
	if err == nil {
		t.Fatal(
			"snapshot accepted replacement inode",
		)
	}

	if !strings.Contains(
		err.Error(),
		"identity or metadata changed",
	) {
		t.Fatalf(
			"unexpected error = %v",
			err,
		)
	}
}

func TestRequireSORPostgreSQLUnmanagedFileSnapshotRejectsContentDrift(
	t *testing.T,
) {
	root, uid, gid :=
		testSORPostgreSQLInitializedRoot(
			t,
		)

	target := filepath.Join(
		root,
		"pg_hba.conf",
	)

	snapshot, err :=
		captureSORPostgreSQLUnmanagedFileSnapshot(
			target,
			uid,
			gid,
		)
	if err != nil {
		t.Fatal(err)
	}

	file, err := os.OpenFile(
		target,
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

	err =
		requireSORPostgreSQLUnmanagedFileSnapshot(
			snapshot,
		)
	if err == nil {
		t.Fatal(
			"snapshot accepted content drift",
		)
	}

	if !strings.Contains(
		err.Error(),
		"content changed",
	) {
		t.Fatalf(
			"unexpected error = %v",
			err,
		)
	}
}

func TestBuildSORPostgreSQLManagedMainConfigPreservesGeneratedContent(
	t *testing.T,
) {
	current := []byte(
		"# generated PostgreSQL configuration\n" +
			"shared_buffers = 128MB\n",
	)

	include := []byte(
		"# FI-MANAGED-BEGIN\n" +
			"include = 'fi-postgresql.conf'\n" +
			"# FI-MANAGED-END\n",
	)

	actual :=
		buildSORPostgreSQLManagedMainConfig(
			current,
			include,
		)

	expected := append(
		append(
			[]byte(nil),
			current...,
		),
		include...,
	)

	if !bytes.Equal(
		actual,
		expected,
	) {
		t.Fatalf(
			"managed main configuration differs:\n%q",
			actual,
		)
	}

	if !bytes.Equal(
		current,
		[]byte(
			"# generated PostgreSQL configuration\n"+
				"shared_buffers = 128MB\n",
		),
	) {
		t.Fatal(
			"source generated configuration was modified",
		)
	}
}

func TestBuildSORPostgreSQLManagedMainConfigAddsMissingNewline(
	t *testing.T,
) {
	actual :=
		buildSORPostgreSQLManagedMainConfig(
			[]byte(
				"shared_buffers = 128MB",
			),
			[]byte(
				"include = 'fi-postgresql.conf'\n",
			),
		)

	expected := []byte(
		"shared_buffers = 128MB\n" +
			"include = 'fi-postgresql.conf'\n",
	)

	if !bytes.Equal(
		actual,
		expected,
	) {
		t.Fatalf(
			"managed main configuration = %q, want %q",
			actual,
			expected,
		)
	}
}
