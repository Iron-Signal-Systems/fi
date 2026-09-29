// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

var (
	liveGMSALogonCLIDLL = syscall.NewLazyDLL(
		"logoncli.dll",
	)

	liveNetIsServiceAccountProc = liveGMSALogonCLIDLL.NewProc(
		"NetIsServiceAccount",
	)
)

func TestLiveApproval2GMSANativeStateCharacterization(
	t *testing.T,
) {
	if os.Getenv(
		"FI_LIVE_GMSA_STATE",
	) != "1" {
		t.Skip(
			"set FI_LIVE_GMSA_STATE=1 to characterize native gMSA state",
		)
	}

	report := Discover()

	if report.Host.BuildNumber != 14393 {
		t.Fatalf(
			"live characterization requires Windows Server 2016 build 14393; observed=%d",
			report.Host.BuildNumber,
		)
	}

	identities, err := DeriveDesiredFIIdentities(
		report.Host.Computer,
		report.Join.Name,
	)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf(
		"computer=%s computer_sid=%s domain=%s dc=%s",
		report.Host.Computer,
		report.AD.ComputerSID,
		report.Join.Name,
		report.AD.DomainController,
	)

	for _, identity := range desiredFIIdentityList(
		identities,
	) {
		adState, adFound := findADGMSA(
			report.AD.GMSAs,
			identity.SAMAccountName,
		)

		if adFound {
			t.Logf(
				"%s AD: present sam=%s dn=%q dns=%q trustee_exact=%t trustees=%s",
				identity.Role,
				identity.SAMAccountName,
				adState.DistinguishedName,
				adState.DNSHostName,
				exactSingleGMSATrustee(
					adState.PasswordRetrievalTrustees,
					report.AD.ComputerSID,
				),
				formatGMSATrustees(
					adState.PasswordRetrievalTrustees,
				),
			)
		} else {
			t.Logf(
				"%s AD: absent sam=%s",
				identity.Role,
				identity.SAMAccountName,
			)
		}

		netlogonPresent, err :=
			liveNetIsServiceAccount(
				identity.SAMAccountName,
			)
		if err != nil {
			t.Logf(
				"%s NetIsServiceAccount: sam=%s error=%v",
				identity.Role,
				identity.SAMAccountName,
				err,
			)
		} else {
			t.Logf(
				"%s NetIsServiceAccount: sam=%s present=%t",
				identity.Role,
				identity.SAMAccountName,
				netlogonPresent,
			)
		}

		queryState, queryErr :=
			queryManagedServiceAccountState(
				identity.SAMAccountName,
			)

		if queryErr != nil {
			t.Logf(
				"%s NetQueryServiceAccount: sam=%s error=%v",
				identity.Role,
				identity.SAMAccountName,
				queryErr,
			)
		} else {
			t.Logf(
				"%s NetQueryServiceAccount: sam=%s state=%s",
				identity.Role,
				identity.SAMAccountName,
				queryState,
			)

			if strings.EqualFold(
				queryState,
				"can_install",
			) {
				t.Fatalf(
					"gMSA %s unexpectedly returned can_install",
					identity.SAMAccountName,
				)
			}
		}

		if adFound &&
			strings.EqualFold(
				identity.SAMAccountName,
				"gFI-ADMINBOX$",
			) {
			if err != nil {
				t.Fatalf(
					"installed collector gMSA NetIsServiceAccount failed: %v",
					err,
				)
			}

			if !netlogonPresent {
				t.Fatal(
					"installed collector gMSA is absent from the local Netlogon store",
				)
			}

			if queryErr != nil {
				t.Fatalf(
					"installed collector gMSA NetQueryServiceAccount failed: %v",
					queryErr,
				)
			}

			if queryState != "installed" {
				t.Fatalf(
					"collector gMSA query state=%s want=installed",
					queryState,
				)
			}
		}
	}
}

func liveNetIsServiceAccount(
	samAccountName string,
) (bool, error) {
	samAccountName, err :=
		serviceAccountSAMName(
			samAccountName,
		)
	if err != nil {
		return false, err
	}

	accountName, err :=
		syscall.UTF16PtrFromString(
			samAccountName,
		)
	if err != nil {
		return false, fmt.Errorf(
			"encode managed service account %q: %w",
			samAccountName,
			err,
		)
	}

	var isService int32

	status, _, _ :=
		liveNetIsServiceAccountProc.Call(
			0,
			uintptr(
				unsafe.Pointer(
					accountName,
				),
			),
			uintptr(
				unsafe.Pointer(
					&isService,
				),
			),
		)

	if status != 0 {
		return false, fmt.Errorf(
			"NetIsServiceAccount %q: NTSTATUS=0x%08x",
			samAccountName,
			uint32(status),
		)
	}

	return isService != 0, nil
}
