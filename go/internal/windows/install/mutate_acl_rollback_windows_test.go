// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"errors"
	"strings"
	"testing"
)

func TestJoinACLMutationRollbackFailurePreservesMutationFailure(
	t *testing.T,
) {
	t.Parallel()

	mutationErr := errors.New(
		"synthetic ACL mutation failure",
	)

	got := joinACLMutationRollbackFailure(
		mutationErr,
		func() error {
			return nil
		},
	)

	if !errors.Is(
		got,
		mutationErr,
	) {
		t.Fatalf(
			"ACL mutation failure was not preserved: %v",
			got,
		)
	}
}

func TestJoinACLMutationRollbackFailureReportsRollbackFailure(
	t *testing.T,
) {
	t.Parallel()

	mutationErr := errors.New(
		"synthetic ACL mutation failure",
	)

	rollbackErr := errors.New(
		"synthetic ACL rollback failure",
	)

	got := joinACLMutationRollbackFailure(
		mutationErr,
		func() error {
			return rollbackErr
		},
	)

	if !errors.Is(
		got,
		mutationErr,
	) {
		t.Fatalf(
			"combined ACL error lost mutation failure: %v",
			got,
		)
	}

	if !errors.Is(
		got,
		rollbackErr,
	) {
		t.Fatalf(
			"combined ACL error lost rollback failure: %v",
			got,
		)
	}

	for _, expected := range []string{
		"synthetic ACL mutation failure",
		"synthetic ACL rollback failure",
		"rollback FI ACL mutations",
	} {
		if !strings.Contains(
			got.Error(),
			expected,
		) {
			t.Fatalf(
				"combined ACL error missing %q: %v",
				expected,
				got,
			)
		}
	}
}

func TestJoinACLMutationRollbackFailureHandlesNilRollback(
	t *testing.T,
) {
	t.Parallel()

	mutationErr := errors.New(
		"synthetic ACL mutation failure",
	)

	got := joinACLMutationRollbackFailure(
		mutationErr,
		nil,
	)

	if !errors.Is(
		got,
		mutationErr,
	) {
		t.Fatalf(
			"nil rollback changed ACL mutation failure: %v",
			got,
		)
	}
}
