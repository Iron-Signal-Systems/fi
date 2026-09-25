// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package recordingest

import (
	"context"
	"testing"
	"time"
)

func TestLoadDueSourceRecordRetryGenerationIDsRequiresConnection(
	t *testing.T,
) {
	_, err := LoadDueSourceRecordRetryGenerationIDs(
		context.Background(),
		nil,
		"source-1",
		time.Now(),
		64,
	)
	if err == nil {
		t.Fatal("nil retry connection was accepted")
	}
}

func TestSourceRecordRejectionRecordedRequiresCompleteIdentity(
	t *testing.T,
) {
	_, err := SourceRecordRejectionRecorded(
		context.Background(),
		nil,
		"attempt-1",
		"source-1",
		"generation-1",
	)
	if err == nil {
		t.Fatal("nil rejection verification connection was accepted")
	}
}
