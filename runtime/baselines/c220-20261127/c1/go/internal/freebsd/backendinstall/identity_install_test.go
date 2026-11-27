// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIdentitySpecsMatchAcceptedContract(t *testing.T) {
	config := loadTestConfig(t)

	specs, err := identitySpecs(config)
	if err != nil {
		t.Fatalf(
			"identitySpecs() error = %v",
			err,
		)
	}

	if len(specs) != 2 {
		t.Fatalf(
			"identity count = %d, want 2",
			len(specs),
		)
	}

	if specs[0].User != "fi-receiver" ||
		specs[0].Group != "fi-receiver" ||
		specs[0].UID != 4100 ||
		specs[0].GID != 4100 {
		t.Fatalf(
			"receiver identity = %#v",
			specs[0],
		)
	}

	if specs[1].User != "fi-ingest" ||
		specs[1].Group != "fi-ingest" ||
		specs[1].UID != 4100 ||
		specs[1].GID != 4100 {
		t.Fatalf(
			"ingest identity = %#v",
			specs[1],
		)
	}
}

func TestInspectIdentityStateAbsent(t *testing.T) {
	spec := identityTestRoot(
		t,
		"",
		"",
	)

	if state := inspectIdentityState(spec); state != identityAbsent {
		t.Fatalf(
			"state = %s, want %s",
			state,
			identityAbsent,
		)
	}
}

func TestInspectIdentityStateExactMatch(t *testing.T) {
	spec := identityTestRoot(
		t,
		"fi-receiver:*:4100:4100::0:0:FI:/nonexistent:/usr/sbin/nologin\n",
		"fi-receiver:*:4100:\n",
	)

	if state := inspectIdentityState(spec); state != identityOwnedMatch {
		t.Fatalf(
			"state = %s, want %s",
			state,
			identityOwnedMatch,
		)
	}
}

func TestInspectIdentityStateForeignUIDCollision(t *testing.T) {
	spec := identityTestRoot(
		t,
		"other:*:4100:4100::0:0:Other:/nonexistent:/usr/sbin/nologin\n",
		"other:*:4100:\n",
	)

	if state := inspectIdentityState(spec); state != identityForeignCollision {
		t.Fatalf(
			"state = %s, want %s",
			state,
			identityForeignCollision,
		)
	}
}

func TestInspectIdentityStateOwnedDrift(t *testing.T) {
	spec := identityTestRoot(
		t,
		"fi-receiver:*:4100:4100::0:0:FI:/wrong:/usr/sbin/nologin\n",
		"fi-receiver:*:4100:\n",
	)

	if state := inspectIdentityState(spec); state != identityOwnedDrift {
		t.Fatalf(
			"state = %s, want %s",
			state,
			identityOwnedDrift,
		)
	}
}

func TestSystemIdentityMutatorUsesAcceptedPwCommands(t *testing.T) {
	calls := make(
		[][]string,
		0,
	)

	mutator := systemIdentityMutator{
		execute: func(
			executable string,
			args ...string,
		) ([]byte, error) {
			call := append(
				[]string{executable},
				args...,
			)

			calls = append(
				calls,
				call,
			)

			return nil, nil
		},
	}

	spec := identitySpec{
		GID:   4100,
		Group: "fi-receiver",
		Root:  "/usr/local/jails/containers/fi-receiver",
		UID:   4100,
		User:  "fi-receiver",
	}

	if err := mutator.Create(spec); err != nil {
		t.Fatalf(
			"Create() error = %v",
			err,
		)
	}

	if len(calls) != 2 {
		t.Fatalf(
			"pw call count = %d, want 2",
			len(calls),
		)
	}

	expectedGroup := []string{
		"/usr/sbin/pw",
		"-R",
		"/usr/local/jails/containers/fi-receiver",
		"groupadd",
		"-n",
		"fi-receiver",
		"-g",
		"4100",
	}

	expectedUser := []string{
		"/usr/sbin/pw",
		"-R",
		"/usr/local/jails/containers/fi-receiver",
		"useradd",
		"-n",
		"fi-receiver",
		"-u",
		"4100",
		"-g",
		"fi-receiver",
		"-d",
		"/nonexistent",
		"-s",
		"/usr/sbin/nologin",
		"-w",
		"no",
	}

	assertStringSliceEqual(
		t,
		calls[0],
		expectedGroup,
	)

	assertStringSliceEqual(
		t,
		calls[1],
		expectedUser,
	)
}

func assertStringSliceEqual(
	t *testing.T,
	actual []string,
	expected []string,
) {
	t.Helper()

	if len(actual) != len(expected) {
		t.Fatalf(
			"length = %d, want %d\nactual=%v",
			len(actual),
			len(expected),
			actual,
		)
	}

	for index := range expected {
		if actual[index] != expected[index] {
			t.Fatalf(
				"element %d = %q, want %q",
				index,
				actual[index],
				expected[index],
			)
		}
	}
}

func identityTestRoot(
	t *testing.T,
	passwd string,
	group string,
) identitySpec {
	t.Helper()

	root := t.TempDir()
	etc := filepath.Join(
		root,
		"etc",
	)

	if err := os.Mkdir(
		etc,
		0755,
	); err != nil {
		t.Fatalf(
			"Mkdir() error = %v",
			err,
		)
	}

	if err := os.WriteFile(
		filepath.Join(
			etc,
			"master.passwd",
		),
		[]byte(passwd),
		0600,
	); err != nil {
		t.Fatalf(
			"write master.passwd: %v",
			err,
		)
	}

	if err := os.WriteFile(
		filepath.Join(
			etc,
			"group",
		),
		[]byte(group),
		0644,
	); err != nil {
		t.Fatalf(
			"write group: %v",
			err,
		)
	}

	return identitySpec{
		GID:   4100,
		Group: "fi-receiver",
		Root:  root,
		UID:   4100,
		User:  "fi-receiver",
	}
}
