// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package usn

import (
	"context"
	"path/filepath"
	"testing"
)

func TestCachedUSNReobservationRejectsWrongScopeBeforeIOTouch(t *testing.T) {
	batch := parallelTestBatch(2)
	// Reject an inconsistent source batch without starting an operation or
	// opening a live journal. This test does not need installed FI services.
	_, err := ReobserveCapturedJournaledStaged(
		context.Background(), "wrong-scope", `F:\Governed`, batch,
		filepath.Join(t.TempDir(), "checkpoint.json"), 256, 32,
	)
	if err == nil {
		t.Fatal("cached processor accepted wrong source scope")
	}
}

func TestCachedUSNReobservationRejectsCanceledBeforeIOTouch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := ReobserveCapturedJournaledStaged(
		ctx, "scope-test", `F:\Governed`, parallelTestBatch(1),
		filepath.Join(t.TempDir(), "checkpoint.json"), 256, 32,
	)
	if err == nil {
		t.Fatal("cached processor accepted canceled operation")
	}
}
