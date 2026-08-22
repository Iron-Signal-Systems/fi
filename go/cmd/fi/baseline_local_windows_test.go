// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func TestCurrentDomainRelatedSIDsIncludesLocalMembershipDomainSID(t *testing.T) {
	identity := records.ProcessIdentityObservation{}
	identity.Computer.NetBIOSName = "SERVER1"
	identity.Token.User.DomainName = "ISS"
	identity.Token.User.SID = "S-1-5-21-1-2-3-1106"
	identity.Token.Groups = append(identity.Token.Groups, records.TokenGroupObservation{
		Principal: records.TokenPrincipalObservation{SID: "S-1-5-21-1-2-3-513"},
	})
	local := records.LocalPrincipalSnapshot{Memberships: []records.LocalGroupMembershipObservation{
		{GroupSID: "S-1-5-32-544", MemberSID: "S-1-5-21-1-2-3-2100"},
		{GroupSID: "S-1-5-32-545", MemberSID: "S-1-1-0"},
	}}
	got := currentDomainRelatedSIDs(identity, local, true)
	want := []string{"S-1-5-21-1-2-3-1106", "S-1-5-21-1-2-3-2100", "S-1-5-21-1-2-3-513"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}
