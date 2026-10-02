// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReplaceFileSetRollsBackEarlierReplacementOnLaterFailure(
	t *testing.T,
) {
	t.Parallel()

	root := t.TempDir()

	sourceOne := filepath.Join(
		root,
		"source-one.exe",
	)

	destinationOne := filepath.Join(
		root,
		"installed-one.exe",
	)

	if err := os.WriteFile(
		sourceOne,
		[]byte("new-one"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(
		destinationOne,
		[]byte("old-one"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	missingSource := filepath.Join(
		root,
		"missing-source.exe",
	)

	_, err := replaceFileSet(
		[]fileReplacement{
			{
				Source:      sourceOne,
				Destination: destinationOne,
			},
			{
				Source: missingSource,

				Destination: filepath.Join(
					root,
					"installed-two.exe",
				),
			},
		},
		"rollback-later-failure",
	)

	if err == nil {
		t.Fatal(
			"later replacement failure unexpectedly succeeded",
		)
	}

	got, err := os.ReadFile(
		destinationOne,
	)
	if err != nil {
		t.Fatal(err)
	}

	if string(got) != "old-one" {
		t.Fatalf(
			"earlier destination=%q want restored old content",
			string(got),
		)
	}

	for _, suffix := range []string{
		".fi-new-rollback-later-failure",
		".fi-old-rollback-later-failure",
	} {
		if _, err := os.Lstat(
			destinationOne + suffix,
		); !os.IsNotExist(
			err,
		) {
			t.Fatalf(
				"transaction artifact remains %s; stat err=%v",
				destinationOne+suffix,
				err,
			)
		}
	}
}

func TestReplaceFileSetRollsBackCurrentFileAfterActivatedHashMismatch(
	t *testing.T,
) {
	t.Parallel()

	root := t.TempDir()

	source := filepath.Join(
		root,
		"source.exe",
	)

	destination := filepath.Join(
		root,
		"installed.exe",
	)

	if err := os.WriteFile(
		source,
		[]byte("new-content"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(
		destination,
		[]byte("old-content"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	_, err := replaceFileSet(
		[]fileReplacement{
			{
				Source:         source,
				Destination:    destination,
				ExpectedSHA256: strings.Repeat("0", 64),
			},
		},
		"rollback-current-file",
	)

	if err == nil {
		t.Fatal(
			"activated hash mismatch unexpectedly succeeded",
		)
	}

	if !strings.Contains(
		err.Error(),
		"hash mismatch",
	) {
		t.Fatalf(
			"unexpected error: %v",
			err,
		)
	}

	got, err := os.ReadFile(
		destination,
	)
	if err != nil {
		t.Fatal(err)
	}

	if string(got) != "old-content" {
		t.Fatalf(
			"destination=%q want restored old content",
			string(got),
		)
	}

	for _, suffix := range []string{
		".fi-new-rollback-current-file",
		".fi-old-rollback-current-file",
	} {
		if _, err := os.Lstat(
			destination + suffix,
		); !os.IsNotExist(
			err,
		) {
			t.Fatalf(
				"transaction artifact remains %s; stat err=%v",
				destination+suffix,
				err,
			)
		}
	}
}

func TestRunFIRecoveryStepsReportsAllFailures(
	t *testing.T,
) {
	t.Parallel()

	first := errors.New(
		"synthetic first recovery failure",
	)

	second := errors.New(
		"synthetic second recovery failure",
	)

	got := runFIRecoverySteps(
		fiRecoveryStep{
			name: "first recovery",
			run: func() error {
				return first
			},
		},
		fiRecoveryStep{
			name: "successful recovery",
			run: func() error {
				return nil
			},
		},
		fiRecoveryStep{
			name: "second recovery",
			run: func() error {
				return second
			},
		},
	)

	if got == nil {
		t.Fatal(
			"multiple synthetic recovery failures returned nil",
		)
	}

	if !errors.Is(
		got,
		first,
	) {
		t.Fatalf(
			"first recovery failure was lost: %v",
			got,
		)
	}

	if !errors.Is(
		got,
		second,
	) {
		t.Fatalf(
			"second recovery failure was lost: %v",
			got,
		)
	}

	for _, expected := range []string{
		"first recovery",
		"second recovery",
		"synthetic first recovery failure",
		"synthetic second recovery failure",
	} {
		if !strings.Contains(
			got.Error(),
			expected,
		) {
			t.Fatalf(
				"combined recovery error missing %q: %v",
				expected,
				got,
			)
		}
	}
}

func TestJoinFIRecoveryFailuresPreservesPrimaryAndRecoveryFailures(
	t *testing.T,
) {
	t.Parallel()

	primary := errors.New(
		"synthetic package failure",
	)

	recovery := errors.New(
		"synthetic package recovery failure",
	)

	got := joinFIRecoveryFailures(
		primary,
		fiRecoveryStep{
			name: "package rollback",
			run: func() error {
				return recovery
			},
		},
	)

	if !errors.Is(
		got,
		primary,
	) {
		t.Fatalf(
			"primary package failure was lost: %v",
			got,
		)
	}

	if !errors.Is(
		got,
		recovery,
	) {
		t.Fatalf(
			"package recovery failure was lost: %v",
			got,
		)
	}

	for _, expected := range []string{
		"synthetic package failure",
		"package rollback",
		"synthetic package recovery failure",
	} {
		if !strings.Contains(
			got.Error(),
			expected,
		) {
			t.Fatalf(
				"combined package error missing %q: %v",
				expected,
				got,
			)
		}
	}
}
