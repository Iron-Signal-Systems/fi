// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package freshinstall

import (
	"errors"
	"testing"
)

func allowedInstallerTokenEvidence() InstallerTokenEvidence {
	privileges := make([]InstallerPrivilegeObservation, 0, len(inspectedInstallerPrivileges))
	for _, name := range inspectedInstallerPrivileges {
		privileges = append(privileges, InstallerPrivilegeObservation{Name: name, Present: true})
	}
	return InstallerTokenEvidence{
		UserSID: "S-1-5-21-1000-2000-3000-1100",
		Primary: true,
		Elevated: true,
		ElevationType: installerElevationFull,
		IntegrityRID: installerHighIntegrityRID,
		AdministratorsEnabled: true,
		PrivilegesInspected: true,
		Privileges: privileges,
	}
}

func TestInstallerTokenPolicyAcceptsOnlyObservedElevatedAdministratorPrerequisites(t *testing.T) {
	e := allowedInstallerTokenEvidence()
	if err := AssessInstallerTokenEvidence(e); err != nil {
		t.Fatalf("eligible evidence refused: %v", err)
	}
	e.ElevationType = installerElevationDefault // valid when UAC is disabled
	e.Privileges[0].Present = false
	if err := AssessInstallerTokenEvidence(e); err != nil {
		t.Fatalf("disabled UAC and missing optional privilege refused: %v", err)
	}
}

func TestInstallerTokenPolicyRejectsFalseAdministratorAuthority(t *testing.T) {
	cases := []struct {
		name string
		edit func(*InstallerTokenEvidence)
	}{
		{"SYSTEM is not operator consent", func(e *InstallerTokenEvidence) { e.UserSID = journalSystemSID }},
		{"NetworkService is not administrator", func(e *InstallerTokenEvidence) { e.UserSID = "S-1-5-20" }},
		{"LocalService is not administrator", func(e *InstallerTokenEvidence) { e.UserSID = "S-1-5-19" }},
		{"empty user", func(e *InstallerTokenEvidence) { e.UserSID = "" }},
		{"malformed user", func(e *InstallerTokenEvidence) { e.UserSID = "S-1-5-21-1\nattack" }},
		{"not primary", func(e *InstallerTokenEvidence) { e.Primary = false }},
		{"thread impersonation", func(e *InstallerTokenEvidence) { e.ThreadImpersonating = true }},
		{"UAC not elevated", func(e *InstallerTokenEvidence) { e.Elevated = false }},
		{"Administrators disabled", func(e *InstallerTokenEvidence) { e.AdministratorsEnabled = false }},
		{"restricted", func(e *InstallerTokenEvidence) { e.Restricted = true }},
		{"app container", func(e *InstallerTokenEvidence) { e.AppContainer = true }},
		{"UAC limited", func(e *InstallerTokenEvidence) { e.ElevationType = 3 }},
		{"UAC type unknown", func(e *InstallerTokenEvidence) { e.ElevationType = 0 }},
		{"medium integrity", func(e *InstallerTokenEvidence) { e.IntegrityRID = 0x2000 }},
		{"low integrity", func(e *InstallerTokenEvidence) { e.IntegrityRID = 0x1000 }},
		{"SYSTEM integrity not interactive", func(e *InstallerTokenEvidence) { e.IntegrityRID = 0x4000 }},
		{"unknown integrity", func(e *InstallerTokenEvidence) { e.IntegrityRID = 0 }},
		{"privilege info missing", func(e *InstallerTokenEvidence) { e.PrivilegesInspected = false }},
		{"privilege list missing", func(e *InstallerTokenEvidence) { e.Privileges = nil }},
		{"privilege list incomplete", func(e *InstallerTokenEvidence) { e.Privileges = e.Privileges[:3] }},
		{"privilege duplicate", func(e *InstallerTokenEvidence) { e.Privileges[1] = e.Privileges[0] }},
		{"privilege unknown", func(e *InstallerTokenEvidence) { e.Privileges[0].Name = "SeUntrustedPrivilege" }},
		{"privilege impossible enabled", func(e *InstallerTokenEvidence) { e.Privileges[0].Present = false; e.Privileges[0].Enabled = true }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := allowedInstallerTokenEvidence()
			tc.edit(&e)
			if err := AssessInstallerTokenEvidence(e); !errors.Is(err, ErrUnqualifiedInstallerToken) {
				t.Fatalf("unsafe installer evidence accepted: %+v, err=%v", e, err)
			}
		})
	}
}
