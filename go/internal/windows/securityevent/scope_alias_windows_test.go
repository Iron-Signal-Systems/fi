// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package securityevent

import (
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func TestNativeWindowsTraversalRejected(t *testing.T) {
	aliases, err := driveRootAliases(`F:\FI-Governed-10M`, `\Device\HarddiskVolume6`, `\\?\Volume{18fed846-4275-4251-b698-f268192100f2}\`)
	if err != nil {
		t.Fatal(err)
	}
	event := records.WindowsSecurityEventObservation{
		EventID: "4656", ObjectType: "File",
		ObjectName: `\Device\HarddiskVolume6\FI-Governed-10M\..\Windows\file.dat`,
	}
	if _, ok := SelectEvent(event, []GovernedScope{{ScopeID: "root-a", GovernedRoot: `F:\FI-Governed-10M`, Aliases: aliases}}); ok {
		t.Fatal("parent traversal escaped governed root but was selected")
	}
}
