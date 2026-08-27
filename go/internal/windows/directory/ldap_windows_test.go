// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows && (amd64 || arm64)

package directory

import "testing"

func TestFormatWindowsGUID(t *testing.T) {
	raw := []byte{0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a, 0xf0, 0xde, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	if got, want := formatWindowsGUID(raw), "12345678-9abc-def0-1122-334455667788"; got != want {
		t.Fatalf("GUID = %q, want %q", got, want)
	}
}

func TestPrincipalLDAPAttributesPreservePrimaryGroupIDRaw(t *testing.T) {
	for _, attr := range principalLDAPAttributes() {
		if attr == "primaryGroupID" {
			return
		}
	}
	t.Fatal("principal LDAP attributes do not include primaryGroupID")
}

func TestLDAPFilterEscapeValue(t *testing.T) {
	got := ldapFilterEscapeValue("CN=Smith (Ops)*\\Test\x00,DC=iss,DC=local")
	want := "CN=Smith \\28Ops\\29\\2a\\5cTest\\00,DC=iss,DC=local"
	if got != want {
		t.Fatalf("escaped filter value = %q, want %q", got, want)
	}
}
