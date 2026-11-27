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

func TestJoinApproval2RollbackFailurePreservesPrimaryFailure(
	t *testing.T,
) {
	t.Parallel()

	primary := errors.New(
		"synthetic operational mutation failure",
	)

	got := joinApproval2RollbackFailure(
		primary,
		"synthetic rollback",
		func() error {
			return nil
		},
	)

	if !errors.Is(
		got,
		primary,
	) {
		t.Fatalf(
			"primary failure was not preserved: %v",
			got,
		)
	}
}

func TestJoinApproval2RollbackFailureReportsRollbackFailure(
	t *testing.T,
) {
	t.Parallel()

	primary := errors.New(
		"synthetic operational mutation failure",
	)

	rollback := errors.New(
		"synthetic operational rollback failure",
	)

	got := joinApproval2RollbackFailure(
		primary,
		"rollback activated FI operational configuration",
		func() error {
			return rollback
		},
	)

	if !errors.Is(
		got,
		primary,
	) {
		t.Fatalf(
			"primary failure was not preserved: %v",
			got,
		)
	}

	if !errors.Is(
		got,
		rollback,
	) {
		t.Fatalf(
			"rollback failure was not preserved: %v",
			got,
		)
	}

	for _, expected := range []string{
		"synthetic operational mutation failure",
		"synthetic operational rollback failure",
		"rollback activated FI operational configuration",
	} {
		if !strings.Contains(
			got.Error(),
			expected,
		) {
			t.Fatalf(
				"combined error missing %q: %v",
				expected,
				got,
			)
		}
	}
}

func TestJoinApproval2RollbackFailureHandlesNilRollback(
	t *testing.T,
) {
	t.Parallel()

	primary := errors.New(
		"synthetic operational mutation failure",
	)

	got := joinApproval2RollbackFailure(
		primary,
		"",
		nil,
	)

	if !errors.Is(
		got,
		primary,
	) {
		t.Fatalf(
			"nil rollback changed primary failure: %v",
			got,
		)
	}
}
