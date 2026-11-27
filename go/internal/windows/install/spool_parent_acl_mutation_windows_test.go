// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"fmt"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestGrantSpoolParentSenderAccessPreservesParentACL(
	t *testing.T,
) {
	t.Parallel()

	parent := t.TempDir()

	senderSID, err := windows.StringToSid(
		"S-1-5-21-112233445-223344556-334455667-1234",
	)
	if err != nil {
		t.Fatal(err)
	}

	before, err := discoverACL(
		parent,
		spoolParentDirectoryACLLabel,
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := grantSpoolParentSenderAccess(
		parent,
		senderSID,
	); err != nil {
		t.Fatal(err)
	}

	after, err := discoverACL(
		parent,
		spoolParentDirectoryACLLabel,
	)
	if err != nil {
		t.Fatal(err)
	}

	if before.Owner != after.Owner {
		t.Fatal("parent owner changed")
	}

	if before.Protected != after.Protected {
		t.Fatal("parent inheritance changed")
	}

	seen := 0

	for _, entry := range after.Entries {
		if strings.EqualFold(
			entry.SID,
			senderSID.String(),
		) {
			seen++

			if entry.Type != "ALLOW" ||
				entry.Mask != spoolParentSenderMask ||
				entry.Flags != 0 ||
				entry.Inherited {
				t.Fatalf(
					"incorrect sender parent ACE: %+v",
					entry,
				)
			}
		}
	}

	if seen != 1 {
		t.Fatalf(
			"sender ACE count=%d want=1",
			seen,
		)
	}

	for _, original := range before.Entries {
		found := false

		for _, observed := range after.Entries {
			if original.SID == observed.SID &&
				original.Type == observed.Type &&
				original.Mask == observed.Mask &&
				original.Flags == observed.Flags {
				found = true
				break
			}
		}

		if !found {
			t.Fatalf(
				"existing parent ACE lost: %+v",
				original,
			)
		}
	}

	if err := grantSpoolParentSenderAccess(
		parent,
		senderSID,
	); err == nil {
		t.Fatal("duplicate sender ACL mutation accepted")
	}
}

func TestGrantSpoolParentSenderAccessRejectsVolumeRoot(
	t *testing.T,
) {
	t.Parallel()

	senderSID, err := windows.StringToSid(
		"S-1-5-21-112233445-223344556-334455667-1234",
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := grantSpoolParentSenderAccess(
		`C:\`,
		senderSID,
	); err == nil {
		t.Fatal(
			fmt.Sprintf("volume root ACL mutation was accepted"),
		)
	}
}
