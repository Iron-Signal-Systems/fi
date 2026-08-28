// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package smb

import (
	"context"
	"errors"
	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"testing"
)

func TestCollectLocalShares(t *testing.T) {
	snapshot, err := CollectLocalShares(context.Background())
	if err != nil {
		var statusErr *netAPIStatusError
		if errors.As(err, &statusErr) && statusErr.Status == netAPIErrorAccessDenied {
			t.Skipf("NetShareEnum level 502 unavailable to this test identity: %v", err)
		}
		t.Fatal(err)
	}
	if len(snapshot.Shares) == 0 {
		t.Fatal("local SMB share snapshot is empty")
	}
	if err := records.ValidateSMBShareSnapshot(snapshot); err != nil {
		t.Fatal(err)
	}

	foundIPC := false
	for _, share := range snapshot.Shares {
		if share.NameDisplay == "IPC$" {
			foundIPC = true
		}
	}
	if !foundIPC {
		t.Log("IPC$ was not returned; snapshot still validated")
	}
}
