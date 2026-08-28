// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package process

import (
	"strconv"
	"strings"
	"testing"
)

func TestCurrentIdentity(t *testing.T) {
	observation, err := CurrentIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if observation.Computer.NetBIOSName == "" {
		t.Fatal("NetBIOS computer name is empty")
	}
	if !strings.HasPrefix(observation.Token.User.SID, "S-") {
		t.Fatalf("user SID = %q", observation.Token.User.SID)
	}
	if observation.Token.TokenTypeName != "Primary" {
		t.Fatalf("token type = %s", observation.Token.TokenTypeName)
	}
	for i, group := range observation.Token.Groups {
		if group.Index != strconv.Itoa(i) {
			t.Fatalf("group[%d].index = %s", i, group.Index)
		}
		if !strings.HasPrefix(group.Principal.SID, "S-") {
			t.Fatalf("group[%d].SID = %q", i, group.Principal.SID)
		}
	}
}

func TestCurrentProcessResourceSnapshot(t *testing.T) {
	snapshot, err := Current()
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.WorkingSetBytes == 0 {
		t.Fatal("working set is zero")
	}
	if snapshot.PeakWorkingSetBytes < snapshot.WorkingSetBytes {
		t.Fatalf("peak working set %d is less than current working set %d", snapshot.PeakWorkingSetBytes, snapshot.WorkingSetBytes)
	}
}

func TestCurrentProcessIOCountersAreReadable(t *testing.T) {
	before, err := Current()
	if err != nil {
		t.Fatal(err)
	}
	after, err := Current()
	if err != nil {
		t.Fatal(err)
	}
	if after.ReadOperationCount < before.ReadOperationCount {
		t.Fatal("read operation counter moved backward")
	}
	if after.WriteOperationCount < before.WriteOperationCount {
		t.Fatal("write operation counter moved backward")
	}
	if after.OtherOperationCount < before.OtherOperationCount {
		t.Fatal("other operation counter moved backward")
	}
}

func TestWindowsVersion(t *testing.T) {
	version, err := WindowsVersion()
	if err != nil {
		t.Fatal(err)
	}
	if version == "" {
		t.Fatal("Windows version is empty")
	}
}

func TestTokenInformationBufferSizeAcceptsBoundedSize(t *testing.T) {
	got, err := tokenInformationBufferSize(maximumTokenInformationBuffer)
	if err != nil {
		t.Fatal(err)
	}
	if got != int(maximumTokenInformationBuffer) {
		t.Fatalf("size = %d, want %d", got, maximumTokenInformationBuffer)
	}
}

func TestTokenInformationBufferSizeRejectsInvalidSize(t *testing.T) {
	if _, err := tokenInformationBufferSize(0); err == nil {
		t.Fatal("expected zero-size rejection")
	}
	if _, err := tokenInformationBufferSize(maximumTokenInformationBuffer + 1); err == nil {
		t.Fatal("expected oversized token-buffer rejection")
	}
}
