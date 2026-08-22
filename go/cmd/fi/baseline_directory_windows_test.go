// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func TestCurrentDomainTokenSIDs(t *testing.T) {
	identity := records.ProcessIdentityObservation{
		Computer: records.ComputerIdentity{NetBIOSName: "ADMINBOX", DNSDomain: "iss.local"},
		Token: records.ProcessTokenObservation{
			User: records.TokenPrincipalObservation{SID: "S-1-5-21-1-2-3-1106", DomainName: "ISS"},
			Groups: []records.TokenGroupObservation{
				{Principal: records.TokenPrincipalObservation{SID: "S-1-5-21-1-2-3-512"}},
				{Principal: records.TokenPrincipalObservation{SID: "S-1-5-32-544"}},
				{Principal: records.TokenPrincipalObservation{SID: "S-1-5-21-1-2-3-513"}},
			},
		},
	}

	got := currentDomainTokenSIDs(identity)
	want := []string{
		"S-1-5-21-1-2-3-1106",
		"S-1-5-21-1-2-3-512",
		"S-1-5-21-1-2-3-513",
	}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestAccountDomainSIDPrefixRejectsNonDomainSID(t *testing.T) {
	if _, ok := accountDomainSIDPrefix("S-1-5-32-544"); ok {
		t.Fatal("expected BUILTIN SID rejection")
	}
}

func TestCurrentDomainTokenSIDsRejectsLocalAccount(t *testing.T) {
	identity := records.ProcessIdentityObservation{
		Computer: records.ComputerIdentity{NetBIOSName: "ADMINBOX", DNSDomain: "iss.local"},
		Token: records.ProcessTokenObservation{
			User: records.TokenPrincipalObservation{SID: "S-1-5-21-9-8-7-1001", DomainName: "ADMINBOX"},
		},
	}
	if got := currentDomainTokenSIDs(identity); len(got) != 0 {
		t.Fatalf("local account produced domain SIDs: %#v", got)
	}
}
