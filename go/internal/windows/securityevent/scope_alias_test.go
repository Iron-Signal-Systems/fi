// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package securityevent

import (
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func TestDriveRootAliasesF22A(t *testing.T) {
	aliases, err := driveRootAliases(`F:\FI-Governed-10M`, `\Device\HarddiskVolume6`, `\\?\Volume{18fed846-4275-4251-b698-f268192100f2}\`)
	if err != nil {
		t.Fatal(err)
	}
	if aliases[0] != `\Device\HarddiskVolume6\FI-Governed-10M` ||
		aliases[1] != `\\?\Volume{18fed846-4275-4251-b698-f268192100f2}\FI-Governed-10M` {
		t.Fatalf("aliases=%q", aliases)
	}
}

func TestNativeWindowsScopeSelection(t *testing.T) {
	aliases, err := driveRootAliases(`F:\FI-Governed-10M`, `\Device\HarddiskVolume6`, `\\?\Volume{18fed846-4275-4251-b698-f268192100f2}\`)
	if err != nil {
		t.Fatal(err)
	}
	scopes := []GovernedScope{{ScopeID: "root-a", GovernedRoot: `F:\FI-Governed-10M`, Aliases: aliases}}
	for _, path := range []string{
		`F:\FI-Governed-10M\10m-run\file.dat`,
		`\Device\HarddiskVolume6\FI-Governed-10M\10m-run\file.dat`,
		`\\?\Volume{18fed846-4275-4251-b698-f268192100f2}\FI-Governed-10M\10m-run\file.dat`,
	} {
		event := records.WindowsSecurityEventObservation{EventID: "4663", ObjectType: "File", ObjectName: path}
		got, ok := SelectEvent(event, scopes)
		if !ok || len(got.MatchedScopes) != 1 || got.ObjectName != path {
			t.Fatalf("must retain event path and match scope: %q %+v %t", path, got, ok)
		}
	}
	for _, path := range []string{
		`\Device\HarddiskVolume5\FI-Governed-10M\file.dat`,
		`\Device\HarddiskVolume6\FI-Governed-10M-OLD\file.dat`,
		`\\?\Volume{d699e0ce-cd7a-4867-a838-cc9f939ef959}\FI-Governed-10M\file.dat`,
	} {
		if _, ok := SelectEvent(records.WindowsSecurityEventObservation{EventID: "4656", ObjectType: "File", ObjectName: path}, scopes); ok {
			t.Fatalf("out-of-scope event accepted: %q", path)
		}
	}
}

func TestUnsafeDeviceAliasesRejected(t *testing.T) {
	for _, device := range []string{`\??\C:`, `\Device\HarddiskVolume6\Other`, `\Device\CdRom0`} {
		if _, err := driveRootAliases(`F:\FI-Governed-10M`, device, `\\?\Volume{18fed846-4275-4251-b698-f268192100f2}\`); err == nil {
			t.Fatalf("accepted unsafe or indirect NT device mapping %q", device)
		}
	}
	if _, err := driveRootAliases(`F:\FI-Governed-10M`, `\Device\HarddiskVolume6`, `\Device\HarddiskVolume6\`); err == nil {
		t.Fatal("non-volume GUID accepted")
	}
	if _, err := driveRootAliases(`F:FI-Governed-10M`, `\Device\HarddiskVolume6`, `\\?\Volume{18fed846-4275-4251-b698-f268192100f2}\`); err == nil {
		t.Fatal("relative drive root accepted")
	}
}

func TestF22BOriginalDrivePathUnchanged(t *testing.T) {
	event := records.WindowsSecurityEventObservation{EventID: "4656", ObjectType: "File", ObjectName: `C:\FI-Governed-Test\file.dat`}
	got, ok := SelectEvent(event, []GovernedScope{{ScopeID: "root-b", GovernedRoot: `C:\FI-Governed-Test`}})
	if !ok || got.ObjectName != event.ObjectName || len(got.MatchedScopes) != 1 {
		t.Fatalf("existing C: path behavior changed: %+v ok=%t", got, ok)
	}
	if strings.Contains(got.ObjectName, `HarddiskVolume`) {
		t.Fatal("original forensic path changed")
	}
}
