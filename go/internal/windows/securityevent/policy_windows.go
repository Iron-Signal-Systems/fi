// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package securityevent

import (
	"errors"
	"fmt"
	"strconv"
	"syscall"
	"unsafe"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

const (
	auditSuccess = 0x00000001
	auditFailure = 0x00000002
)

var (
	advapi32                   = syscall.NewLazyDLL("advapi32.dll")
	procAuditQuerySystemPolicy = advapi32.NewProc("AuditQuerySystemPolicy")
	procAuditFree              = advapi32.NewProc("AuditFree")
)

type windowsGUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

type auditPolicyInformation struct {
	SubCategoryGuid     windowsGUID
	AuditingInformation uint32
	CategoryGuid        windowsGUID
}

var (
	_ [36 - unsafe.Sizeof(auditPolicyInformation{})]byte
	_ [unsafe.Sizeof(auditPolicyInformation{}) - 36]byte
)

var (
	fileSystemAuditGUID = windowsGUID{
		Data1: 0x0CCE921D, Data2: 0x69AE, Data3: 0x11D9,
		Data4: [8]byte{0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30},
	}
	handleManipulationAuditGUID = windowsGUID{
		Data1: 0x0CCE9223, Data2: 0x69AE, Data3: 0x11D9,
		Data4: [8]byte{0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30},
	}
	detailedFileShareAuditGUID = windowsGUID{
		Data1: 0x0CCE9244, Data2: 0x69AE, Data3: 0x11D9,
		Data4: [8]byte{0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30},
	}
	auditPolicyChangeGUID = windowsGUID{
		Data1: 0x0CCE922F, Data2: 0x69AE, Data3: 0x11D9,
		Data4: [8]byte{0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30},
	}
)

const (
	FileSystemAuditSubcategoryGUID    = "{0CCE921D-69AE-11D9-BED3-505054503030}"
	HandleManipulationSubcategoryGUID = "{0CCE9223-69AE-11D9-BED3-505054503030}"
	DetailedFileShareSubcategoryGUID  = "{0CCE9244-69AE-11D9-BED3-505054503030}"
	AuditPolicyChangeSubcategoryGUID  = "{0CCE922F-69AE-11D9-BED3-505054503030}"
)

func QueryRequiredAuditPolicy() (records.WindowsSecurityAuditPolicyObservation, records.WindowsSecurityAuditPolicyObservation, error) {
	fileSystem, err := queryAuditPolicy(fileSystemAuditGUID, FileSystemAuditSubcategoryGUID)
	if err != nil {
		return records.WindowsSecurityAuditPolicyObservation{}, records.WindowsSecurityAuditPolicyObservation{}, err
	}
	policyChange, err := queryAuditPolicy(auditPolicyChangeGUID, AuditPolicyChangeSubcategoryGUID)
	if err != nil {
		return records.WindowsSecurityAuditPolicyObservation{}, records.WindowsSecurityAuditPolicyObservation{}, err
	}
	return fileSystem, policyChange, nil
}

func queryAuditPolicy(guid windowsGUID, textGUID string) (records.WindowsSecurityAuditPolicyObservation, error) {
	var output *auditPolicyInformation
	r1, _, callErr := procAuditQuerySystemPolicy.Call(
		uintptr(unsafe.Pointer(&guid)),
		1,
		uintptr(unsafe.Pointer(&output)),
	)
	if r1 == 0 {
		if callErr != nil && !errors.Is(callErr, syscall.Errno(0)) {
			return records.WindowsSecurityAuditPolicyObservation{}, callErr
		}
		return records.WindowsSecurityAuditPolicyObservation{}, errors.New("AuditQuerySystemPolicy failed")
	}
	if output == nil {
		return records.WindowsSecurityAuditPolicyObservation{}, errors.New("AuditQuerySystemPolicy returned no policy")
	}
	defer procAuditFree.Call(uintptr(unsafe.Pointer(output)))

	flags := output.AuditingInformation
	return records.WindowsSecurityAuditPolicyObservation{
		SubcategoryGUID:     textGUID,
		AuditingInformation: strconv.FormatUint(uint64(flags), 10),
		SuccessEnabled:      flags&auditSuccess != 0,
		FailureEnabled:      flags&auditFailure != 0,
	}, nil
}

func auditPolicyDescription(value records.WindowsSecurityAuditPolicyObservation) string {
	return fmt.Sprintf(
		"%s success=%t failure=%t raw=%s",
		value.SubcategoryGUID,
		value.SuccessEnabled,
		value.FailureEnabled,
		value.AuditingInformation,
	)
}
