// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package freshinstall

import (
	"errors"
	"fmt"
	"strings"
)

var ErrUnqualifiedInstallerToken = errors.New("FI v2 native installer token does not meet isolated administrator preflight")

const (
	installerTokenPrimary uint32 = 1
	installerElevationDefault uint32 = 1
	installerElevationFull uint32 = 2
	installerHighIntegrityRID uint32 = 0x3000

	maxInstallerPrivileges = 256
)

// InstallerPrivilegeObservation is a diagnostic snapshot of one privileged
// Windows LUID. Enabled means SE_PRIVILEGE_ENABLED was observed; it never
// means this code enabled a privilege. Missing or disabled privileges are
// NOT automatically enabled to make an installer preflight pass.
type InstallerPrivilegeObservation struct {
	Name string
	Present bool
	Enabled bool
}

var inspectedInstallerPrivileges = [...]string{
	"SeBackupPrivilege",
	"SeRestorePrivilege",
	"SeSecurityPrivilege",
	"SeTakeOwnershipPrivilege",
	"SeImpersonatePrivilege",
	"SeDebugPrivilege",
}

// InstallerTokenEvidence is an immutable-by-convention snapshot of an actual
// Windows process token on one locked OS thread. Native code must collect
// every field, including failed/uncertain queries, before applying policy.
// This object is not a cryptographic signed grant, issuer, or consent record.
type InstallerTokenEvidence struct {
	UserSID string
	Primary bool
	ThreadImpersonating bool
	Elevated bool
	ElevationType uint32
	IntegrityRID uint32
	AdministratorsEnabled bool
	Restricted bool
	AppContainer bool
	PrivilegesInspected bool
	Privileges []InstallerPrivilegeObservation
}

// AssessInstallerTokenEvidence checks whether an ACTUAL native process-token
// snapshot satisfies the narrow preconditions for a *future interactive*
// elevated administrator installer. LocalSystem, NetworkService, LocalService,
// low/medium integrity, UAC-limited, deny-only-admin, restricted, app-container,
// and impersonating-thread contexts are not eligible.
//
// This is deliberately NOT installer authorization. A genuine high-integrity
// admin token could still belong to the wrong operator or compromised host.
// Authenticated operator consent, issuer, signed grant, trusted parent handle
// and complete installation transaction remain separate mandatory gates.
func AssessInstallerTokenEvidence(e InstallerTokenEvidence) error {
	if len(e.UserSID) < 8 || len(e.UserSID) > 184 ||
		!strings.HasPrefix(e.UserSID, "S-1-5-") ||
		strings.ContainsAny(e.UserSID, "\x00 \t\r\n") ||
		e.UserSID == journalSystemSID || e.UserSID == "S-1-5-19" ||
		e.UserSID == "S-1-5-20" {
		return fmt.Errorf("%w: missing or service-account token user", ErrUnqualifiedInstallerToken)
	}
	if !e.Primary || e.ThreadImpersonating || !e.Elevated ||
		!e.AdministratorsEnabled || e.Restricted || e.AppContainer {
		return fmt.Errorf("%w: process is not an elevated, nonrestricted, nonimpersonating administrator primary token", ErrUnqualifiedInstallerToken)
	}
	if e.ElevationType != installerElevationDefault &&
		e.ElevationType != installerElevationFull {
		return fmt.Errorf("%w: limited or unknown UAC elevation type %d", ErrUnqualifiedInstallerToken, e.ElevationType)
	}
	// A SYSTEM process is not an interactive administrator approval path.
	// Future service install actions require their own authority model.
	if e.IntegrityRID != installerHighIntegrityRID {
		return fmt.Errorf("%w: expected high integrity (0x3000), observed 0x%x", ErrUnqualifiedInstallerToken, e.IntegrityRID)
	}
	if !e.PrivilegesInspected || len(e.Privileges) != len(inspectedInstallerPrivileges) {
		return fmt.Errorf("%w: missing bounded privilege inventory", ErrUnqualifiedInstallerToken)
	}
	seen := make(map[string]bool, len(inspectedInstallerPrivileges))
	for _, p := range e.Privileges {
		expected := false
		for _, name := range inspectedInstallerPrivileges {
			if p.Name == name {
				expected = true
				break
			}
		}
		if !expected || seen[p.Name] || (!p.Present && p.Enabled) {
			return fmt.Errorf("%w: duplicate, unknown or inconsistent privilege observation", ErrUnqualifiedInstallerToken)
		}
		seen[p.Name] = true
	}
	// Observing SeBackup/SeRestore/SeSecurity/SeDebug/etc. is not a grant and
	// their present/disabled status depends on the real Windows environment.
	// Never adjust them silently or treat enabled rights as operator consent.
	return nil
}
