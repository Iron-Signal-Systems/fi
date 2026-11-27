// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestSpoolParentAndRawACLConvergence(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	sender := `ISS\gFI-FS19$`
	spoolDir := filepath.Join(root, "spool")

	report := Report{
		Config: ConfigState{
			Path:     filepath.Join(root, "config", "fi.conf"),
			SpoolDir: spoolDir,
			StageDir: filepath.Join(root, "stage"),
			StateDir: filepath.Join(root, "state"),
		},
		ACLs: []ACLState{
			{
				Label:     spoolParentDirectoryACLLabel,
				Path:      root,
				Owner:     `NT AUTHORITY\SYSTEM`,
				Protected: false,
				Entries: []ACLEntry{
					{
						Account: `BUILTIN\Administrators`,
						Type:    "ALLOW",
						Mask:    fileFullControlMask,
					},
					{
						Account: `NT AUTHORITY\SYSTEM`,
						Type:    "ALLOW",
						Mask:    fileFullControlMask,
					},
					{
						Account:   sender,
						Type:      "ALLOW",
						Mask:      fileReadExecuteMask | 0x4,
						Flags:     0,
						Inherited: false,
					},
				},
			},
			{
				Label:     generationRawDirectoryACLLabel,
				Path:      filepath.Join(root, "generation-raw"),
				Owner:     `BUILTIN\Administrators`,
				Protected: true,
				Entries: []ACLEntry{
					{
						Account: `BUILTIN\Administrators`,
						Type:    "ALLOW",
						Mask:    fileFullControlMask,
					},
					{
						Account: `NT AUTHORITY\SYSTEM`,
						Type:    "ALLOW",
						Mask:    fileFullControlMask,
					},
					{
						Account: sender,
						Type:    "ALLOW",
						Mask:    fileModifyMask,
					},
				},
			},
		},
	}

	evaluateDesiredACLContractsForAccounts(
		&report,
		sender,
		`ISS\gFI-CRL-FS19$`,
		`ISS\gFI-USN-FS19$`,
		`ISS\gFI-OBJ-FS19$`,
	)

	var plan InstallPlan
	planACLs(&plan, report)

	for _, target := range []string{
		root,
		filepath.Join(root, "generation-raw"),
	} {
		found := false

		for _, action := range plan.Actions {
			if action.Authority != "ACL" ||
				!filepath.IsAbs(action.Target) ||
				!filepath.IsAbs(target) ||
				!filepathEqualFold(action.Target, target) {
				continue
			}

			found = true

			if action.Action != planActionNoChange {
				t.Errorf(
					"compliant ACL target %q: action=%s, want NO CHANGE; detail=%s",
					target, action.Action, action.Detail,
				)
			}
		}

		if !found {
			t.Errorf("no ACL action for %q", target)
		}
	}
}

func filepathEqualFold(left, right string) bool {
	return strings.EqualFold(
		filepath.Clean(left),
		filepath.Clean(right),
	)
}
