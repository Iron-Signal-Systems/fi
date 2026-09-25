// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package objbroker

import (
	"context"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func TestObserveObjectRejectsUnsupportedIdentityBeforePipe(t *testing.T) {
	_, err := ObserveObject(
		context.Background(),
		`C:\FI-Lab`,
		records.NTFSObjectIdentity{
			MethodVersion:       "unsupported",
			FileReferenceNumber: "1",
			SequenceNumber:      "1",
		},
	)
	if err == nil {
		t.Fatal("expected unsupported identity-method rejection")
	}
}
