// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func aclEntryCounts(state ACLState) map[string]int {
	result := make(map[string]int)

	for _, entry := range state.Entries {
		key := fmt.Sprintf(
			"%s/%s/%08X/%02X/%t",
			strings.ToUpper(entry.SID),
			entry.Type,
			entry.Mask,
			entry.Flags,
			entry.Inherited,
		)
		result[key]++
	}

	return result
}

func TestSpoolParentACLRollbackAndNoChildInheritance(t *testing.T) {
	parent := t.TempDir()

	sid, err := windows.StringToSid(
		"S-1-5-21-112233445-223344556-334455667-1234",
	)
	if err != nil {
		t.Fatal(err)
	}

	originalSDDL, err := captureNamedSecurityDescriptorSDDL(parent)
	if err != nil {
		t.Fatal(err)
	}

	before, err := discoverACL(parent, spoolParentDirectoryACLLabel)
	if err != nil {
		t.Fatal(err)
	}

	if err := grantSpoolParentSenderAccess(parent, sid); err != nil {
		t.Fatal(err)
	}

	rollbackNeeded := true

	t.Cleanup(func() {
		if rollbackNeeded {
			if err := restoreNamedSecurityDescriptorFromSDDL(
				parent, originalSDDL,
			); err != nil {
				t.Errorf("cleanup rollback failed: %v", err)
			}
		}
	})

	child := filepath.Join(parent, "unrelated-child")

	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}

	childACL, err := discoverACL(child, "test child")
	if err != nil {
		t.Fatal(err)
	}

	for _, entry := range childACL.Entries {
		if strings.EqualFold(entry.SID, sid.String()) {
			t.Fatalf(
				"sender permission leaked into child: %+v",
				entry,
			)
		}
	}

	if err := restoreNamedSecurityDescriptorFromSDDL(
		parent, originalSDDL,
	); err != nil {
		t.Fatal(err)
	}
	rollbackNeeded = false

	after, err := discoverACL(parent, spoolParentDirectoryACLLabel)
	if err != nil {
		t.Fatal(err)
	}

	if before.Owner != after.Owner ||
		before.Protected != after.Protected {
		t.Fatal("rollback changed ownership or inheritance")
	}

	if !reflect.DeepEqual(
		aclEntryCounts(before),
		aclEntryCounts(after),
	) {
		t.Fatalf(
			"rollback did not restore original ACEs: before=%v after=%v",
			aclEntryCounts(before),
			aclEntryCounts(after),
		)
	}
}

func TestSpoolParentACLSecurityRejectsInvalidSenderACE(t *testing.T) {
	sender := `ISS\gFI-FS19$`

	valid := ACLEntry{
		Account: sender,
		Type:    "ALLOW",
		Mask:    spoolParentSenderMask,
	}

	tests := []struct {
		name    string
		entries []ACLEntry
	}{
		{
			name: "missing permission",
		},
		{
			name: "missing create subdirectory",
			entries: []ACLEntry{{
				Account: sender,
				Type:    "ALLOW",
				Mask:    fileReadExecuteMask,
			}},
		},
		{
			name: "excessive modify permission",
			entries: []ACLEntry{{
				Account: sender,
				Type:    "ALLOW",
				Mask:    fileModifyMask,
			}},
		},
		{
			name: "inheritable sender permission",
			entries: []ACLEntry{{
				Account: sender,
				Type:    "ALLOW",
				Mask:    spoolParentSenderMask,
				Flags:   windows.CONTAINER_INHERIT_ACE,
			}},
		},
		{
			name: "inherited sender permission",
			entries: []ACLEntry{{
				Account:   sender,
				Type:      "ALLOW",
				Mask:      spoolParentSenderMask,
				Flags:     windows.INHERITED_ACE,
				Inherited: true,
			}},
		},
		{
			name: "explicit deny",
			entries: []ACLEntry{
				valid,
				{
					Account: sender,
					Type:    "DENY",
					Mask:    spoolParentSenderMask,
				},
			},
		},
		{
			name: "additional excessive allow",
			entries: []ACLEntry{
				valid,
				{
					Account: sender,
					Type:    "ALLOW",
					Mask:    fileModifyMask,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := Report{
				ACLs: []ACLState{{
					Label:   spoolParentDirectoryACLLabel,
					Entries: tt.entries,
				}},
			}

			evaluateSpoolParentDirectoryACL(&report, sender)

			result, found := findCheck(
				report,
				spoolParentDirectoryACLLabel+" desired ACL contract",
			)

			if !found {
				t.Fatal("ACL evaluation check missing")
			}

			if result.Status != checkFail {
				t.Fatalf(
					"unsafe ACL accepted: status=%s detail=%s",
					result.Status,
					result.Detail,
				)
			}
		})
	}
}
