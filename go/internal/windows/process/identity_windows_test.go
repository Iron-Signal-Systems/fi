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
