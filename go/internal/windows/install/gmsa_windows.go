// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	msaInfoNotExist      = uint32(1)
	msaInfoNotService    = uint32(2)
	msaInfoCannotInstall = uint32(3)
	msaInfoCanInstall    = uint32(4)
	msaInfoInstalled     = uint32(5)
)

type DomainJoinState struct {
	Name   string
	Status string
}

type GMSAState struct {
	Account        string
	Role           string
	SAMAccountName string
	State          string
}

var (
	logoncliManagedServiceDLL = syscall.NewLazyDLL(
		"logoncli.dll",
	)
	netapi32ManagedServiceDLL = syscall.NewLazyDLL(
		"netapi32.dll",
	)

	netIsServiceAccountProc = logoncliManagedServiceDLL.NewProc(
		"NetIsServiceAccount",
	)
	netQueryServiceAccountProc = netapi32ManagedServiceDLL.NewProc(
		"NetQueryServiceAccount",
	)
)

func discoverDomainJoin(report *Report) {
	var name *uint16
	var joinStatus uint32

	err := windows.NetGetJoinInformation(
		nil,
		&name,
		&joinStatus,
	)
	if err != nil {
		report.Join = DomainJoinState{
			Name:   notKnown,
			Status: notKnown,
		}
		report.addCheck(
			checkFail,
			"Windows domain join",
			err.Error(),
		)
		return
	}
	if name != nil {
		defer windows.NetApiBufferFree(
			(*byte)(unsafe.Pointer(name)),
		)
	}

	report.Join = DomainJoinState{
		Name:   valueOrNotKnown(windows.UTF16PtrToString(name)),
		Status: domainJoinStatusName(joinStatus),
	}

	if joinStatus != windows.NetSetupDomainName {
		report.addCheck(
			checkFail,
			"Windows domain join",
			fmt.Sprintf(
				"status=%s name=%s",
				report.Join.Status,
				report.Join.Name,
			),
		)
		return
	}

	report.addCheck(
		checkPass,
		"Windows domain join",
		fmt.Sprintf(
			"status=%s name=%s",
			report.Join.Status,
			report.Join.Name,
		),
	)
}

func discoverGMSAs(report *Report) {
	identities, err := DeriveDesiredFIIdentities(
		report.Host.Computer,
		report.Join.Name,
	)
	if err != nil {
		report.addCheck(
			checkFail,
			"FI managed service account naming",
			err.Error(),
		)
		return
	}

	seen := make(map[string]struct{})

	for _, item := range desiredFIIdentityList(identities) {
		account := item.Account
		sam := item.SAMAccountName

		key := strings.ToLower(sam)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}

		if !report.AD.GMSADiscoveryKnown {
			report.GMSAs = append(
				report.GMSAs,
				GMSAState{
					Account:        account,
					Role:           item.Role,
					SAMAccountName: sam,
					State:          notKnown,
				},
			)
			report.addCheck(
				checkFail,
				item.Role+" managed service account",
				"Active Directory gMSA discovery is not authoritative; FI did not query local Netlogon service-account state",
			)
			continue
		}

		if _, found := findADGMSA(
			report.AD.GMSAs,
			sam,
		); !found {
			report.GMSAs = append(
				report.GMSAs,
				GMSAState{
					Account:        account,
					Role:           item.Role,
					SAMAccountName: sam,
					State:          "pending_ad_creation",
				},
			)
			report.addCheck(
				checkInfo,
				item.Role+" managed service account",
				fmt.Sprintf(
					"AD authoritatively confirms sam=%s is absent; local Netlogon service-account state is not queried until Approval 1 creates the gMSA",
					sam,
				),
			)
			continue
		}

		present, err := localManagedServiceAccountPresent(
			sam,
		)
		if err != nil {
			report.GMSAs = append(
				report.GMSAs,
				GMSAState{
					Account:        account,
					Role:           item.Role,
					SAMAccountName: sam,
					State:          notKnown,
				},
			)
			report.addCheck(
				checkFail,
				item.Role+" managed service account",
				err.Error(),
			)
			continue
		}

		state := "not_installed"
		status := checkInfo
		if present {
			state = "installed"
			status = checkPass
		}

		detail := fmt.Sprintf(
			"account=%s sam=%s ad=present netlogon_present=%t state=%s",
			account,
			sam,
			present,
			state,
		)

		report.GMSAs = append(
			report.GMSAs,
			GMSAState{
				Account:        account,
				Role:           item.Role,
				SAMAccountName: sam,
				State:          state,
			},
		)
		report.addCheck(
			status,
			item.Role+" managed service account",
			detail,
		)
	}
}

func domainJoinStatusName(value uint32) string {
	switch value {
	case windows.NetSetupUnknownStatus:
		return "unknown"
	case windows.NetSetupUnjoined:
		return "unjoined"
	case windows.NetSetupWorkgroupName:
		return "workgroup"
	case windows.NetSetupDomainName:
		return "domain"
	default:
		return fmt.Sprintf("not_known(%d)", value)
	}
}

func localManagedServiceAccountPresent(
	samAccountName string,
) (bool, error) {
	samAccountName, err := serviceAccountSAMName(
		samAccountName,
	)
	if err != nil {
		return false, err
	}

	accountName, err := syscall.UTF16PtrFromString(
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

	status, _, _ := netIsServiceAccountProc.Call(
		0,
		uintptr(unsafe.Pointer(accountName)),
		uintptr(unsafe.Pointer(&isService)),
	)
	if status != 0 {
		return false, fmt.Errorf(
			"query local Netlogon service-account presence %q: NTSTATUS=0x%08x",
			samAccountName,
			uint32(status),
		)
	}

	return isService != 0, nil
}

func managedServiceAccountStateName(value uint32) string {
	switch value {
	case msaInfoNotExist:
		return "not_exist"
	case msaInfoNotService:
		return "not_managed_service_account"
	case msaInfoCannotInstall:
		return "cannot_install"
	case msaInfoCanInstall:
		return "can_install"
	case msaInfoInstalled:
		return "installed"
	default:
		return fmt.Sprintf("not_known(%d)", value)
	}
}

func queryManagedServiceAccountState(
	samAccountName string,
) (string, error) {
	accountName, err := syscall.UTF16PtrFromString(
		samAccountName,
	)
	if err != nil {
		return "", fmt.Errorf(
			"encode managed service account %q: %w",
			samAccountName,
			err,
		)
	}

	var buffer uintptr

	status, _, _ := netQueryServiceAccountProc.Call(
		0,
		uintptr(unsafe.Pointer(accountName)),
		0,
		uintptr(unsafe.Pointer(&buffer)),
	)
	if status != 0 {
		return "", fmt.Errorf(
			"query managed service account %q: NTSTATUS=0x%08x",
			samAccountName,
			uint32(status),
		)
	}
	if buffer == 0 {
		return "", fmt.Errorf(
			"query managed service account %q returned no state buffer",
			samAccountName,
		)
	}
	defer windows.NetApiBufferFree(
		(*byte)(unsafe.Pointer(buffer)),
	)

	state := *(*uint32)(unsafe.Pointer(buffer))
	return managedServiceAccountStateName(state), nil
}

func serviceAccountSAMName(account string) (string, error) {
	account = strings.TrimSpace(account)
	if account == "" {
		return "", fmt.Errorf(
			"service account is unavailable",
		)
	}

	if index := strings.LastIndex(account, `\`); index >= 0 {
		account = account[index+1:]
	}

	if account == "" {
		return "", fmt.Errorf(
			"service account SAM name is empty",
		)
	}
	if !strings.HasSuffix(account, "$") {
		return "", fmt.Errorf(
			"service account %q is not a managed-service-account SAM name",
			account,
		)
	}

	return account, nil
}
