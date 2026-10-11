// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

type fakeSORPostgreSQLClusterInitializer struct {
	initialize      func() error
	initializeCalls int
	publish         func() error
	publishCalls    int
}

func (
	initializer *fakeSORPostgreSQLClusterInitializer,
) Initialize() error {
	initializer.initializeCalls++

	if initializer.initialize == nil {
		return nil
	}

	return initializer.initialize()
}

func (
	initializer *fakeSORPostgreSQLClusterInitializer,
) PublishPolicy(
	_ sorPostgreSQLClusterPolicy,
	_ uint64,
	_ uint64,
) error {
	initializer.publishCalls++

	if initializer.publish == nil {
		return nil
	}

	return initializer.publish()
}

func TestInitializeSORPostgreSQLClusterEmptyToOwnedMatch(
	t *testing.T,
) {
	root, spec, policy :=
		testSORPostgreSQLEmptyClusterState(
			t,
		)

	initializer :=
		&fakeSORPostgreSQLClusterInitializer{}

	initializer.initialize = func() error {
		writeTestSORPostgreSQLCluster(
			t,
			root,
		)

		return nil
	}

	initializer.publish = func() error {
		writeTestSORPostgreSQLManagedClusterPolicy(
			t,
			policy,
		)

		return nil
	}

	if err := initializeSORPostgreSQLCluster(
		spec,
		policy,
		initializer,
	); err != nil {
		t.Fatalf(
			"initializeSORPostgreSQLCluster() error = %v",
			err,
		)
	}

	if initializer.initializeCalls != 1 {
		t.Fatalf(
			"Initialize() calls = %d, want 1",
			initializer.initializeCalls,
		)
	}

	if initializer.publishCalls != 1 {
		t.Fatalf(
			"PublishPolicy() calls = %d, want 1",
			initializer.publishCalls,
		)
	}

	if state :=
		classifySORPostgreSQLCluster(
			spec,
		); state != sorPostgreSQLClusterInitialized {
		t.Fatalf(
			"cluster state = %s, want INITIALIZED",
			state,
		)
	}

	if state :=
		classifySORPostgreSQLClusterPolicy(
			policy,
			spec.UID,
			spec.GID,
		); state != sorPostgreSQLClusterPolicyOwnedMatch {
		t.Fatalf(
			"policy state = %s, want OWNED_MATCH",
			state,
		)
	}
}

func TestInitializeSORPostgreSQLClusterExactNoOp(
	t *testing.T,
) {
	root, spec, policy :=
		testSORPostgreSQLEmptyClusterState(
			t,
		)

	writeTestSORPostgreSQLCluster(
		t,
		root,
	)

	writeTestSORPostgreSQLManagedClusterPolicy(
		t,
		policy,
	)

	initializer :=
		&fakeSORPostgreSQLClusterInitializer{}

	if err := initializeSORPostgreSQLCluster(
		spec,
		policy,
		initializer,
	); err != nil {
		t.Fatalf(
			"initializeSORPostgreSQLCluster() error = %v",
			err,
		)
	}

	if initializer.initializeCalls != 0 ||
		initializer.publishCalls != 0 {
		t.Fatalf(
			"unexpected mutation calls: initialize=%d publish=%d",
			initializer.initializeCalls,
			initializer.publishCalls,
		)
	}
}

func TestInitializeSORPostgreSQLClusterRejectsInitializedUnmanaged(
	t *testing.T,
) {
	root, spec, policy :=
		testSORPostgreSQLEmptyClusterState(
			t,
		)

	writeTestSORPostgreSQLCluster(
		t,
		root,
	)

	initializer :=
		&fakeSORPostgreSQLClusterInitializer{}

	err := initializeSORPostgreSQLCluster(
		spec,
		policy,
		initializer,
	)
	if err == nil {
		t.Fatal(
			"initializeSORPostgreSQLCluster accepted initialized unmanaged cluster",
		)
	}

	if !strings.Contains(
		err.Error(),
		"already initialized",
	) {
		t.Fatalf(
			"unexpected error = %v",
			err,
		)
	}

	if initializer.initializeCalls != 0 ||
		initializer.publishCalls != 0 {
		t.Fatalf(
			"mutation executed against initialized unmanaged cluster: initialize=%d publish=%d",
			initializer.initializeCalls,
			initializer.publishCalls,
		)
	}
}

func TestInitializeSORPostgreSQLClusterRejectsPartial(
	t *testing.T,
) {
	root, spec, policy :=
		testSORPostgreSQLEmptyClusterState(
			t,
		)

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

	initializer :=
		&fakeSORPostgreSQLClusterInitializer{}

	err := initializeSORPostgreSQLCluster(
		spec,
		policy,
		initializer,
	)
	if err == nil {
		t.Fatal(
			"initializeSORPostgreSQLCluster accepted partial PGDATA",
		)
	}

	if !strings.Contains(
		err.Error(),
		"partial or foreign",
	) {
		t.Fatalf(
			"unexpected error = %v",
			err,
		)
	}

	if initializer.initializeCalls != 0 ||
		initializer.publishCalls != 0 {
		t.Fatalf(
			"mutation executed against partial PGDATA: initialize=%d publish=%d",
			initializer.initializeCalls,
			initializer.publishCalls,
		)
	}
}

func TestInitializeSORPostgreSQLClusterRejectsAbsent(
	t *testing.T,
) {
	parent := t.TempDir()

	root := filepath.Join(
		parent,
		"absent",
	)

	info, err := os.Lstat(parent)
	if err != nil {
		t.Fatal(err)
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal(
			"test parent does not expose syscall.Stat_t",
		)
	}

	spec := sorPostgreSQLClusterSpec{
		GID:          uint64(stat.Gid),
		MajorVersion: sorPostgreSQLClusterMajorVersion,
		PGData:       root,
		UID:          uint64(stat.Uid),
	}

	policy := testSORPostgreSQLClusterPolicy(
		t,
		root,
	)

	initializer :=
		&fakeSORPostgreSQLClusterInitializer{}

	err = initializeSORPostgreSQLCluster(
		spec,
		policy,
		initializer,
	)
	if err == nil {
		t.Fatal(
			"initializeSORPostgreSQLCluster accepted absent PGDATA",
		)
	}

	if initializer.initializeCalls != 0 ||
		initializer.publishCalls != 0 {
		t.Fatalf(
			"mutation executed against absent PGDATA: initialize=%d publish=%d",
			initializer.initializeCalls,
			initializer.publishCalls,
		)
	}
}

func TestInitializeSORPostgreSQLClusterRejectsPostInitForeignPolicy(
	t *testing.T,
) {
	root, spec, policy :=
		testSORPostgreSQLEmptyClusterState(
			t,
		)

	initializer :=
		&fakeSORPostgreSQLClusterInitializer{}

	initializer.initialize = func() error {
		writeTestSORPostgreSQLCluster(
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

		return nil
	}

	err := initializeSORPostgreSQLCluster(
		spec,
		policy,
		initializer,
	)
	if err == nil {
		t.Fatal(
			"initializeSORPostgreSQLCluster accepted non-UNMANAGED post-init state",
		)
	}

	if !strings.Contains(
		err.Error(),
		"not exact UNMANAGED",
	) {
		t.Fatalf(
			"unexpected error = %v",
			err,
		)
	}

	if initializer.initializeCalls != 1 {
		t.Fatalf(
			"Initialize() calls = %d, want 1",
			initializer.initializeCalls,
		)
	}

	if initializer.publishCalls != 0 {
		t.Fatalf(
			"PublishPolicy() calls = %d, want 0",
			initializer.publishCalls,
		)
	}
}

func TestInitializeSORPostgreSQLClusterPropagatesInitFailure(
	t *testing.T,
) {
	_, spec, policy :=
		testSORPostgreSQLEmptyClusterState(
			t,
		)

	expected := errors.New(
		"initdb failed",
	)

	initializer :=
		&fakeSORPostgreSQLClusterInitializer{
			initialize: func() error {
				return expected
			},
		}

	err := initializeSORPostgreSQLCluster(
		spec,
		policy,
		initializer,
	)
	if err == nil {
		t.Fatal(
			"initializeSORPostgreSQLCluster expected init failure",
		)
	}

	if !strings.Contains(
		err.Error(),
		"initdb failed",
	) {
		t.Fatalf(
			"unexpected error = %v",
			err,
		)
	}

	if initializer.publishCalls != 0 {
		t.Fatalf(
			"PublishPolicy() called after init failure: %d",
			initializer.publishCalls,
		)
	}
}

func TestInitializeSORPostgreSQLClusterPropagatesPublishFailure(
	t *testing.T,
) {
	root, spec, policy :=
		testSORPostgreSQLEmptyClusterState(
			t,
		)

	expected := errors.New(
		"publish failed",
	)

	initializer :=
		&fakeSORPostgreSQLClusterInitializer{}

	initializer.initialize = func() error {
		writeTestSORPostgreSQLCluster(
			t,
			root,
		)

		return nil
	}

	initializer.publish = func() error {
		return expected
	}

	err := initializeSORPostgreSQLCluster(
		spec,
		policy,
		initializer,
	)
	if err == nil {
		t.Fatal(
			"initializeSORPostgreSQLCluster expected publish failure",
		)
	}

	if !strings.Contains(
		err.Error(),
		"publish failed",
	) {
		t.Fatalf(
			"unexpected error = %v",
			err,
		)
	}

	if initializer.initializeCalls != 1 ||
		initializer.publishCalls != 1 {
		t.Fatalf(
			"unexpected mutation calls: initialize=%d publish=%d",
			initializer.initializeCalls,
			initializer.publishCalls,
		)
	}
}

func TestInitializeSORPostgreSQLClusterRejectsFailedFinalVerification(
	t *testing.T,
) {
	root, spec, policy :=
		testSORPostgreSQLEmptyClusterState(
			t,
		)

	initializer :=
		&fakeSORPostgreSQLClusterInitializer{}

	initializer.initialize = func() error {
		writeTestSORPostgreSQLCluster(
			t,
			root,
		)

		return nil
	}

	initializer.publish = func() error {
		return nil
	}

	err := initializeSORPostgreSQLCluster(
		spec,
		policy,
		initializer,
	)
	if err == nil {
		t.Fatal(
			"initializeSORPostgreSQLCluster accepted failed final policy verification",
		)
	}

	if !strings.Contains(
		err.Error(),
		"did not verify",
	) {
		t.Fatalf(
			"unexpected error = %v",
			err,
		)
	}
}

func testSORPostgreSQLEmptyClusterState(
	t *testing.T,
) (
	string,
	sorPostgreSQLClusterSpec,
	sorPostgreSQLClusterPolicy,
) {
	t.Helper()

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

	spec.MajorVersion =
		sorPostgreSQLClusterMajorVersion

	policy := testSORPostgreSQLClusterPolicy(
		t,
		root,
	)

	return root,
		spec,
		policy
}

func TestInitializeSORPostgreSQLClusterDatabaseReadyExactNoOp(
	t *testing.T,
) {
	root, spec, policy :=
		testSORPostgreSQLEmptyClusterState(
			t,
		)

	writeTestSORPostgreSQLCluster(
		t,
		root,
	)

	writeTestSORPostgreSQLManagedClusterPolicy(
		t,
		policy,
	)

	writeTestSORPostgreSQLPolicyFile(
		t,
		policy.HBAPath,
		policy.HBADatabaseReadyContent,
	)

	if state :=
		classifySORPostgreSQLClusterPolicy(
			policy,
			spec.UID,
			spec.GID,
		); state !=
		sorPostgreSQLClusterPolicyOwnedMatch {
		t.Fatalf(
			"database-ready policy state = %s, want OWNED_MATCH",
			state,
		)
	}

	initializer :=
		&fakeSORPostgreSQLClusterInitializer{}

	if err := initializeSORPostgreSQLCluster(
		spec,
		policy,
		initializer,
	); err != nil {
		t.Fatalf(
			"initializeSORPostgreSQLCluster() error = %v",
			err,
		)
	}

	if initializer.initializeCalls != 0 ||
		initializer.publishCalls != 0 {
		t.Fatalf(
			"database-ready state caused mutation: initialize=%d publish=%d",
			initializer.initializeCalls,
			initializer.publishCalls,
		)
	}
}
