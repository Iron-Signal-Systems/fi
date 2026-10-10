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

func TestPlannedACLTargetsUseProposedConfigAndRetainedTrust(
	t *testing.T,
) {
	t.Parallel()

	report := Report{
		Config: ConfigState{
			Path:     `C:\ProgramData\FI\config\fi.conf`,
			Presence: presenceAbsent,
			SpoolDir: `C:\ProgramData\FI\spool`,
			StageDir: `C:\ProgramData\FI\transport-v2-drain\stage`,
			StateDir: `C:\ProgramData\FI\state`,
		},

		Trust: TransportTrustState{
			TransportCRLPath: `C:\ProgramData\FI\pki\trust\fi-transport-ca.crl.pem`,
		},

		ReleaseTrust: ReleaseTrustState{
			Installed: ReleaseTrustDocumentState{
				Present: true,
			},
		},
	}

	targets :=
		plannedACLTargets(
			report,
		)

	got := make(
		map[string]string,
		len(targets),
	)

	for _, target := range targets {
		got[target.Label] =
			filepath.Clean(
				target.Path,
			)
	}

	want := map[string]string{
		"FI config directory": filepath.Clean(
			`C:\ProgramData\FI\config`,
		),

		"FI program directory": filepath.Clean(
			`C:\Program Files\FI`,
		),

		"FI state directory": filepath.Clean(
			`C:\ProgramData\FI\state`,
		),

		"FI spool directory": filepath.Clean(
			`C:\ProgramData\FI\spool`,
		),

		"FI collector work directory": filepath.Clean(
			`C:\ProgramData\FI\.fi-spool-collector-work`,
		),

		"FI stage directory": filepath.Clean(
			`C:\ProgramData\FI\transport-v2-drain\stage`,
		),

		"FI PKI trust directory": filepath.Clean(
			`C:\ProgramData\FI\pki\trust`,
		),

		"FI CRL activation directory": filepath.Clean(
			`C:\ProgramData\FI\pki\crl`,
		),

		"FI CRL active file": filepath.Clean(
			`C:\ProgramData\FI\pki\crl\fi-transport-ca.crl.pem`,
		),

		"FI CRL refresher executable file": filepath.Clean(
			`C:\Program Files\FI\fi-crl-refresher.exe`,
		),

		"FI CRL refresher journal directory": filepath.Clean(
			`C:\ProgramData\FI\crl-refresh`,
		),

		"FI CRL refresher journal file": filepath.Clean(
			`C:\ProgramData\FI\crl-refresh\crl-refresh.jsonl`,
		),

		"FI CRL refresher trust config file": filepath.Clean(
			`C:\ProgramData\FI\config\fi-transport-trust.conf`,
		),

		"FI release trust directory": filepath.Clean(
			installedReleaseTrustRoot,
		),
	}

	if len(got) != len(want) {
		t.Fatalf(
			"ACL target count=%d want=%d got=%v",
			len(got),
			len(want),
			got,
		)
	}

	for label, expected := range want {
		observed, found :=
			got[label]

		if !found {
			t.Fatalf(
				"missing ACL target %q",
				label,
			)
		}

		if !strings.EqualFold(
			observed,
			expected,
		) {
			t.Fatalf(
				"%s path=%q want=%q",
				label,
				observed,
				expected,
			)
		}
	}
}

func TestDesiredACLAccountsDoNotDependOnSCMServicePresence(
	t *testing.T,
) {
	t.Parallel()

	report := Report{
		Host: HostState{
			Computer: "AdminBox",
		},

		Join: DomainJoinState{
			Name: "ISS",
		},

		Services: []ServiceState{
			{
				Name:     "FICollector",
				Presence: presenceAbsent,
			},
			{
				Name:     "FIUSNReader",
				Presence: presenceAbsent,
			},
			{
				Name:     "FIObjReader",
				Presence: presenceAbsent,
			},
			{
				Name:     "FISender",
				Presence: presenceAbsent,
			},
		},
	}

	collector, crlRefresher, usnReader, objReader, err :=
		desiredACLAccounts(
			report,
		)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.EqualFold(
		collector,
		`ISS\gFI-ADMINBOX$`,
	) {
		t.Fatalf(
			"collector/sender=%q want=%q",
			collector,
			`ISS\gFI-ADMINBOX$`,
		)
	}

	if !strings.EqualFold(
		crlRefresher,
		`ISS\gFI-CRL-ADMINBOX$`,
	) {
		t.Fatalf(
			"crl refresher=%q want=%q",
			crlRefresher,
			`ISS\gFI-CRL-ADMINBOX$`,
		)
	}

	if !strings.EqualFold(
		usnReader,
		`ISS\gFI-USN-ADMINBOX$`,
	) {
		t.Fatalf(
			"USN reader=%q want=%q",
			usnReader,
			`ISS\gFI-USN-ADMINBOX$`,
		)
	}

	if !strings.EqualFold(
		objReader,
		`ISS\gFI-OBJ-ADMINBOX$`,
	) {
		t.Fatalf(
			"object reader=%q want=%q",
			objReader,
			`ISS\gFI-OBJ-ADMINBOX$`,
		)
	}
}
