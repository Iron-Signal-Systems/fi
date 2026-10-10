// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const fiCertificateEnrollmentGroupName = "ISS-FI-Certificate-Enrollment"

var (
	netapi32FIInstallDLL         = windows.NewLazySystemDLL("netapi32.dll")
	netGroupAddUserFIInstallProc = netapi32FIInstallDLL.NewProc("NetGroupAddUser")
	netGroupDelUserFIInstallProc = netapi32FIInstallDLL.NewProc("NetGroupDelUser")
)

type machineCertificateEnrollmentAuthorizationMutation struct {
	AddedByTransaction bool
	ComputerSAM        string
	DomainController   string
	GroupName          string
	Managed            bool
}

func machineKerberosPurgePrerequisite() error {
	path, err := exec.LookPath("klist.exe")
	if err != nil {
		return fmt.Errorf("locate klist.exe for SYSTEM Kerberos refresh: %w", err)
	}
	if strings.TrimSpace(path) == "" {
		return errors.New("klist.exe path resolved empty")
	}
	return nil
}

func prepareMachineCertificateEnrollmentAuthorization(
	before Report,
	backend approval1PKIBackend,
) (machineCertificateEnrollmentAuthorizationMutation, error) {
	nativeBackend, ok := backend.(*nativeApproval1PKIBackend)
	if !ok {
		// Unit-test/synthetic backends do not mutate real AD or Kerberos state.
		return machineCertificateEnrollmentAuthorizationMutation{}, nil
	}
	if nativeBackend == nil || nativeBackend.session == nil || nativeBackend.session.handle == 0 {
		return machineCertificateEnrollmentAuthorizationMutation{}, errors.New(
			"native Approval 1 PKI LDAP session is unavailable for machine enrollment authorization",
		)
	}
	return ensureMachineCertificateEnrollmentAuthorization(
		before,
		nativeBackend.session,
	)
}

func ensureMachineCertificateEnrollmentAuthorization(
	before Report,
	session *ldapSession,
) (machineCertificateEnrollmentAuthorizationMutation, error) {
	mutation := machineCertificateEnrollmentAuthorizationMutation{
		DomainController: strings.TrimSpace(before.AD.DomainController),
		GroupName:        fiCertificateEnrollmentGroupName,
		Managed:          true,
	}

	computerSAM := strings.TrimSpace(before.Host.Computer)
	if computerSAM == "" || strings.EqualFold(computerSAM, notKnown) {
		return mutation, errors.New("computer name is unavailable for certificate enrollment authorization")
	}
	if !strings.HasSuffix(computerSAM, "$") {
		computerSAM += "$"
	}
	mutation.ComputerSAM = computerSAM

	if mutation.DomainController == "" || strings.EqualFold(mutation.DomainController, notKnown) {
		return mutation, errors.New("authoritative domain controller is unavailable for certificate enrollment authorization")
	}

	group, err := discoverCertificateEnrollmentGroupPrerequisite(
		session,
		before.AD.DefaultNamingContext,
		fiCertificateEnrollmentGroupName,
	)
	if err != nil {
		return mutation, err
	}

	allowSIDs, _, err := activeDirectoryObjectSIDMembership(
		session,
		before.AD.ComputerDN,
		before.AD.ComputerSID,
	)
	if err != nil {
		return mutation, fmt.Errorf("discover current source-computer group token: %w", err)
	}
	groupSID := strings.ToUpper(strings.TrimSpace(group.SID))
	_, alreadyMember := allowSIDs[groupSID]

	if !alreadyMember {
		status, err := netGroupAddUserOnDomainController(
			mutation.DomainController,
			fiCertificateEnrollmentGroupName,
			computerSAM,
		)
		if err != nil {
			return mutation, err
		}
		if status == 0 {
			mutation.AddedByTransaction = true
		}

		allowSIDs, _, err = activeDirectoryObjectSIDMembership(
			session,
			before.AD.ComputerDN,
			before.AD.ComputerSID,
		)
		if err != nil {
			rollbackErr := rollbackMachineCertificateEnrollmentAuthorization(mutation)
			if rollbackErr != nil {
				return mutation, errors.Join(
					fmt.Errorf("rediscover source-computer group token after membership mutation: %w", err),
					rollbackErr,
				)
			}
			return mutation, fmt.Errorf("rediscover source-computer group token after membership mutation: %w", err)
		}
		if _, found := allowSIDs[groupSID]; !found {
			rollbackErr := rollbackMachineCertificateEnrollmentAuthorization(mutation)
			cause := fmt.Errorf(
				"source computer %s is not present in effective AD tokenGroups for %s after membership mutation on %s",
				computerSAM,
				fiCertificateEnrollmentGroupName,
				mutation.DomainController,
			)
			if rollbackErr != nil {
				return mutation, errors.Join(cause, rollbackErr)
			}
			return mutation, cause
		}
	}

	if err := purgeMachineKerberosTickets(); err != nil {
		rollbackErr := rollbackMachineCertificateEnrollmentAuthorization(mutation)
		if rollbackErr != nil {
			return mutation, errors.Join(err, rollbackErr)
		}
		return mutation, err
	}

	return mutation, nil
}

func rollbackMachineCertificateEnrollmentAuthorization(
	mutation machineCertificateEnrollmentAuthorizationMutation,
) error {
	if !mutation.Managed || !mutation.AddedByTransaction {
		return nil
	}

	var rollbackErrors []error
	if err := netGroupDelUserOnDomainController(
		mutation.DomainController,
		mutation.GroupName,
		mutation.ComputerSAM,
	); err != nil {
		rollbackErrors = append(rollbackErrors, err)
	}
	if err := purgeMachineKerberosTickets(); err != nil {
		rollbackErrors = append(
			rollbackErrors,
			fmt.Errorf("purge SYSTEM Kerberos cache after enrollment-group rollback: %w", err),
		)
	}
	return errors.Join(rollbackErrors...)
}

func netGroupAddUserOnDomainController(
	domainController string,
	groupName string,
	computerSAM string,
) (uint32, error) {
	return netGroupMembershipCall(
		netGroupAddUserFIInstallProc,
		"NetGroupAddUser",
		domainController,
		groupName,
		computerSAM,
	)
}

func netGroupDelUserOnDomainController(
	domainController string,
	groupName string,
	computerSAM string,
) error {
	status, err := netGroupMembershipCall(
		netGroupDelUserFIInstallProc,
		"NetGroupDelUser",
		domainController,
		groupName,
		computerSAM,
	)
	if err != nil {
		return err
	}
	if status != 0 {
		return fmt.Errorf(
			"NetGroupDelUser server=%s group=%s computer=%s returned NET_API_STATUS=%d",
			domainController,
			groupName,
			computerSAM,
			status,
		)
	}
	return nil
}

func netGroupMembershipCall(
	procedure *windows.LazyProc,
	operation string,
	domainController string,
	groupName string,
	computerSAM string,
) (uint32, error) {
	serverName := strings.TrimSpace(domainController)
	if serverName == "" {
		return 0, errors.New("domain controller is required")
	}
	if !strings.HasPrefix(serverName, `\\`) {
		serverName = `\\` + serverName
	}

	serverPointer, err := syscall.UTF16PtrFromString(serverName)
	if err != nil {
		return 0, err
	}
	groupPointer, err := syscall.UTF16PtrFromString(strings.TrimSpace(groupName))
	if err != nil {
		return 0, err
	}
	computerPointer, err := syscall.UTF16PtrFromString(strings.TrimSpace(computerSAM))
	if err != nil {
		return 0, err
	}

	status, _, _ := procedure.Call(
		uintptr(unsafe.Pointer(serverPointer)),
		uintptr(unsafe.Pointer(groupPointer)),
		uintptr(unsafe.Pointer(computerPointer)),
	)
	runtime.KeepAlive(serverPointer)
	runtime.KeepAlive(groupPointer)
	runtime.KeepAlive(computerPointer)

	if uint32(status) != 0 {
		return uint32(status), fmt.Errorf(
			"%s server=%s group=%s computer=%s returned NET_API_STATUS=%d",
			operation,
			serverName,
			groupName,
			computerSAM,
			uint32(status),
		)
	}
	return uint32(status), nil
}

func purgeMachineKerberosTickets() error {
	command := exec.Command(
		"klist.exe",
		"-li",
		"0x3e7",
		"purge",
	)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf(
			"klist -li 0x3e7 purge failed: %w output=%q",
			err,
			strings.TrimSpace(string(output)),
		)
	}
	return nil
}
