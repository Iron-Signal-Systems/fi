// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package freshinstall

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows"
)

// CI queries only its own process token; no FI service, root ACL, token
// privilege or host security setting is modified. The runner may or may
// not be an elevated interactive administrator. Either policy outcome is
// legitimate, but native observation MUST be complete and well-formed.
func TestNativeInstallerTokenInspectionRemainsReadOnly(t *testing.T) {
	e, err := inspectNativeInstallerProcessToken()
	if err != nil {
		t.Fatalf("native process-token query failed (not an authorization decision): %v", err)
	}
	if !e.Primary || e.UserSID == "" || !e.PrivilegesInspected ||
		len(e.Privileges) != len(inspectedInstallerPrivileges) ||
		e.IntegrityRID == 0 {
		t.Fatalf("native installer-token evidence missing mandatory observed fields")
	}
	for i, p := range e.Privileges {
		if p.Name != inspectedInstallerPrivileges[i] || (!p.Present && p.Enabled) {
			t.Fatalf("native privilege observation not bounded/canonical at index %d", i)
		}
	}
	verdict := AssessInstallerTokenEvidence(e)
	if verdict != nil && !errors.Is(verdict, ErrUnqualifiedInstallerToken) {
		t.Fatalf("native token assessment failed without a classified reason: %v", verdict)
	}
	t.Logf("native process token: elevation=%t type=%d admin-enabled=%t integrity=0x%x restricted=%t app-container=%t assessed=%v",
		e.Elevated, e.ElevationType, e.AdministratorsEnabled,
		e.IntegrityRID, e.Restricted, e.AppContainer, verdict)
}

func TestNativeInstallerTokenFunctionsRejectInvalidTokenHandles(t *testing.T) {
	for _, token := range []windows.Token{0, windows.Token(windows.InvalidHandle)} {
		if _, err := queryInstallerTokenDword(token, windows.TokenElevation); !errors.Is(err, ErrUnqualifiedInstallerToken) {
			t.Fatalf("invalid token allowed scalar query: %v", err)
		}
		if _, err := installerTokenIntegrityRID(token); !errors.Is(err, ErrUnqualifiedInstallerToken) {
			t.Fatalf("invalid token allowed integrity query: %v", err)
		}
		if _, err := installerTokenPrivilegesBounded(token); !errors.Is(err, ErrUnqualifiedInstallerToken) {
			t.Fatalf("invalid token allowed privilege query: %v", err)
		}
		if _, err := enabledInstallerAdministratorsGroup(token); !errors.Is(err, ErrUnqualifiedInstallerToken) {
			t.Fatalf("invalid token allowed primary-token group query: %v", err)
		}
		if _, err := queryInstallerTokenBoolean(token, windows.TokenHasRestrictions); !errors.Is(err, ErrUnqualifiedInstallerToken) {
			t.Fatalf("invalid token allowed Boolean token query: %v", err)
		}
	}
}

func TestNativeTokenBooleanWidthsAndMalformedValues(t *testing.T) {
	cases:=[]struct{
		name string
		data [4]byte
		size uint32
		want bool
		valid bool
	}{
		{"BOOLEAN false",[4]byte{},1,false,true},
		{"BOOLEAN true",[4]byte{1},1,true,true},
		{"DWORD false",[4]byte{},4,false,true},
		{"DWORD true",[4]byte{1},4,true,true},
		{"invalid width",[4]byte{1},2,false,false},
		{"missing width",[4]byte{},0,false,false},
		{"bad BOOLEAN",[4]byte{2},1,false,false},
		{"bad DWORD",[4]byte{2},4,false,false},
		{"noncanonical DWORD",[4]byte{1,1,0,0},4,false,false},
	}
	for _,tc:=range cases {
		t.Run(tc.name,func(t *testing.T) {
			got,err:=decodeInstallerTokenBoolean(tc.data,tc.size)
			if tc.valid {
				if err!=nil || got!=tc.want {t.Fatalf("valid token Boolean: got=%t err=%v",got,err)}
			} else if !errors.Is(err,ErrUnqualifiedInstallerToken) {
				t.Fatalf("malformed native Boolean accepted: got=%t err=%v",got,err)
			}
		})
	}
}
