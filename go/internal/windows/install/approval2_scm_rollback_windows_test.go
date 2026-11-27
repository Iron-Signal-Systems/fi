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

func TestFailApproval2SCMTransactionPreservesMutationFailure(
	t *testing.T,
) {
	t.Parallel()

	mutationErr := errors.New(
		"synthetic SCM mutation failure",
	)

	_, _, err := failApproval2SCMTransaction(
		mutationErr,
		func() error {
			return nil
		},
	)
	if err == nil {
		t.Fatal(
			"SCM failure unexpectedly returned nil",
		)
	}

	if !errors.Is(
		err,
		mutationErr,
	) {
		t.Fatalf(
			"returned error does not preserve mutation failure: %v",
			err,
		)
	}
}

func TestFailApproval2SCMTransactionReportsRollbackFailure(
	t *testing.T,
) {
	t.Parallel()

	mutationErr := errors.New(
		"synthetic SCM mutation failure",
	)
	rollbackErr := errors.New(
		"synthetic SCM rollback failure",
	)

	_, _, err := failApproval2SCMTransaction(
		mutationErr,
		func() error {
			return rollbackErr
		},
	)
	if err == nil {
		t.Fatal(
			"combined SCM failure unexpectedly returned nil",
		)
	}

	if !errors.Is(
		err,
		mutationErr,
	) {
		t.Fatalf(
			"combined error does not preserve mutation failure: %v",
			err,
		)
	}

	if !errors.Is(
		err,
		rollbackErr,
	) {
		t.Fatalf(
			"combined error does not preserve rollback failure: %v",
			err,
		)
	}

	for _, expected := range []string{
		"synthetic SCM mutation failure",
		"synthetic SCM rollback failure",
		"rollback Approval 2 SCM transaction",
	} {
		if !strings.Contains(
			err.Error(),
			expected,
		) {
			t.Fatalf(
				"combined error missing %q: %v",
				expected,
				err,
			)
		}
	}
}

func TestFailApproval2SCMTransactionHandlesNilRollback(
	t *testing.T,
) {
	t.Parallel()

	mutationErr := errors.New(
		"synthetic SCM mutation failure",
	)

	_, _, err := failApproval2SCMTransaction(
		mutationErr,
		nil,
	)
	if !errors.Is(
		err,
		mutationErr,
	) {
		t.Fatalf(
			"nil rollback changed mutation failure: %v",
			err,
		)
	}
}
