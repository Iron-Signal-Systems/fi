// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	approval2BatchCNGKeyTargetPrefix     = "FI batch-signing CNG private key SHA256="
	approval2TransportCNGKeyTargetPrefix = "FI transport CNG private key SHA256="

	cngKeyFileReadMask         = uint32(0x00120089)
	cngUniqueNamePropertyName  = "Unique Name"
	fiMachineCNGKeyRelativeDir = `Microsoft\Crypto\Keys`
)

type cngKeyACLMutation struct {
	Path         string
	PreviousSDDL string
}

type cngKeyACLPlanTarget struct {
	CertificateSHA256 string
	Label             string
	Target            string
}

func approval2BatchCNGKeyTarget(
	certificateSHA256 string,
) string {
	return approval2BatchCNGKeyTargetPrefix + strings.ToLower(
		strings.TrimSpace(
			certificateSHA256,
		),
	)
}

func approval2TransportCNGKeyTarget(
	certificateSHA256 string,
) string {
	return approval2TransportCNGKeyTargetPrefix + strings.ToLower(
		strings.TrimSpace(
			certificateSHA256,
		),
	)
}

func appendCNGKeyReadACE(
	sddl string,
	sid string,
) (string, error) {
	sddl = strings.TrimSpace(sddl)
	sid = strings.TrimSpace(sid)

	if sddl == "" {
		return "", errors.New(
			"CNG key security descriptor SDDL is empty",
		)
	}
	if sid == "" || !strings.HasPrefix(sid, "S-1-") {
		return "", fmt.Errorf(
			"CNG key read principal SID is invalid: %q",
			sid,
		)
	}

	daclStart := strings.Index(sddl, "D:")
	if daclStart < 0 {
		return "", errors.New(
			"CNG key security descriptor contains no DACL",
		)
	}

	insertAt := len(sddl)
	if saclOffset := strings.Index(
		sddl[daclStart+2:],
		"S:",
	); saclOffset >= 0 {
		insertAt = daclStart + 2 + saclOffset
	}

	ace := fmt.Sprintf(
		"(A;;0x%08X;;;%s)",
		cngKeyFileReadMask,
		sid,
	)

	return sddl[:insertAt] + ace + sddl[insertAt:], nil
}

func cngKeyACLForbiddenMask() uint32 {
	return uint32(
		windows.FILE_WRITE_DATA |
			windows.FILE_APPEND_DATA |
			windows.FILE_WRITE_EA |
			windows.FILE_WRITE_ATTRIBUTES |
			windows.DELETE |
			windows.WRITE_DAC |
			windows.WRITE_OWNER,
	)
}

func cngKeyACLHasReadOnly(
	state ACLState,
	account string,
) bool {
	forbidden := cngKeyACLForbiddenMask()

	var (
		aggregate uint32
		found     bool
	)

	for _, entry := range state.Entries {
		if entry.Type != "ALLOW" ||
			!accountMatches(
				entry,
				account,
			) {
			continue
		}

		found = true

		// One acceptable Read ACE must not hide a second ALLOW ACE that grants
		// the FI service identity write, delete, or ACL-administration rights.
		if entry.Mask&forbidden != 0 {
			return false
		}

		aggregate |= entry.Mask
	}

	return found &&
		aggregate&cngKeyFileReadMask == cngKeyFileReadMask
}

func cngKeyACLHasForbiddenAllow(
	state ACLState,
	account string,
) (ACLEntry, bool) {
	forbidden := cngKeyACLForbiddenMask()

	for _, entry := range state.Entries {
		if entry.Type != "ALLOW" ||
			!accountMatches(
				entry,
				account,
			) {
			continue
		}

		if entry.Mask&forbidden != 0 {
			return entry, true
		}
	}

	return ACLEntry{}, false
}
func cngKeyACLTargetsFromPlan(
	plan InstallPlan,
) ([]cngKeyACLPlanTarget, error) {
	var result []cngKeyACLPlanTarget
	seen := make(map[string]struct{})

	for _, action := range plan.Actions {
		if action.Authority != "ACL" ||
			!planActionMutates(
				action.Action,
			) {
			continue
		}

		var (
			certificateSHA256 string
			label             string
		)

		switch {
		case strings.HasPrefix(
			action.Target,
			approval2BatchCNGKeyTargetPrefix,
		):
			certificateSHA256 = strings.TrimPrefix(
				action.Target,
				approval2BatchCNGKeyTargetPrefix,
			)
			label = "FI batch-signing CNG key"

		case strings.HasPrefix(
			action.Target,
			approval2TransportCNGKeyTargetPrefix,
		):
			certificateSHA256 = strings.TrimPrefix(
				action.Target,
				approval2TransportCNGKeyTargetPrefix,
			)
			label = "FI transport CNG key"

		default:
			continue
		}

		certificateSHA256 = strings.TrimSpace(
			certificateSHA256,
		)
		if !validSHA256Hex(
			certificateSHA256,
		) {
			return nil, fmt.Errorf(
				"Approval 2 CNG key ACL target contains invalid certificate SHA-256: %q",
				action.Target,
			)
		}

		key := strings.ToLower(
			certificateSHA256,
		)
		if _, duplicate := seen[key]; duplicate {
			return nil, fmt.Errorf(
				"Approval 2 CNG key ACL target duplicates certificate SHA256=%s",
				certificateSHA256,
			)
		}
		seen[key] = struct{}{}

		result = append(
			result,
			cngKeyACLPlanTarget{
				CertificateSHA256: certificateSHA256,
				Label:             label,
				Target:            action.Target,
			},
		)
	}

	return result, nil
}

func discoverCNGKeyACL(
	report *Report,
	checkName string,
	label string,
	certificateSHA256 string,
	account string,
) {
	if !validSHA256Hex(
		certificateSHA256,
	) {
		report.addCheck(
			checkFail,
			checkName,
			"certificate SHA-256 is invalid or unavailable",
		)
		return
	}

	path, err := machineCNGKeyFilePathForCertificateSHA256(
		certificateSHA256,
	)
	if err != nil {
		report.addCheck(
			checkFail,
			checkName,
			err.Error(),
		)
		return
	}

	state, err := discoverACL(
		path,
		label,
	)
	if err != nil {
		report.addCheck(
			checkFail,
			checkName,
			err.Error(),
		)
		return
	}

	report.ACLs = append(
		report.ACLs,
		state,
	)

	if !cngKeyACLHasReadOnly(
		state,
		account,
	) {
		report.addCheck(
			checkFail,
			checkName,
			fmt.Sprintf(
				"account=%s requires Read without write/delete/ACL-administration on exact key file %s",
				account,
				path,
			),
		)
		return
	}

	report.addCheck(
		checkPass,
		checkName,
		fmt.Sprintf(
			"account=%s has Read without write/delete/ACL-administration on exact key file %s",
			account,
			path,
		),
	)
}

func discoverCNGKeyACLs(
	report *Report,
) {
	if report == nil ||
		report.Trust.Presence != presencePresent {
		return
	}

	identities, err := DeriveDesiredFIIdentities(
		report.Host.Computer,
		report.Join.Name,
	)
	if err != nil {
		for _, name := range []string{
			"FI batch-signing CNG key desired ACL contract",
			"FI transport CNG key desired ACL contract",
		} {
			report.addCheck(
				checkFail,
				name,
				"derive collector/sender gMSA identity: "+err.Error(),
			)
		}
		return
	}

	account := identities.CollectorSender.Account

	discoverCNGKeyACL(
		report,
		"FI batch-signing CNG key desired ACL contract",
		"FI batch-signing CNG private key",
		report.Trust.BatchSigningCertificateSHA256,
		account,
	)

	discoverCNGKeyACL(
		report,
		"FI transport CNG key desired ACL contract",
		"FI transport CNG private key",
		report.Trust.TransportCertificateSHA256,
		account,
	)
}

func machineCNGKeyFilePathForCertificateSHA256(
	certificateSHA256 string,
) (string, error) {
	locator, err := localMachineCNGKeyLocatorForCertificateSHA256(
		certificateSHA256,
	)
	if err != nil {
		return "", err
	}

	uniqueName, err := readCNGKeyUniqueName(
		locator,
	)
	if err != nil {
		return "", fmt.Errorf(
			"read CNG unique name for certificate SHA256=%s: %w",
			certificateSHA256,
			err,
		)
	}

	if !validCNGKeyUniqueName(
		uniqueName,
	) {
		return "", fmt.Errorf(
			"CNG unique name for certificate SHA256=%s is unsafe: %q",
			certificateSHA256,
			uniqueName,
		)
	}

	programData := strings.TrimSpace(
		os.Getenv("ProgramData"),
	)
	if programData == "" ||
		!filepath.IsAbs(
			programData,
		) {
		return "", errors.New(
			"ProgramData is unavailable for FI CNG key ACL discovery",
		)
	}

	path := filepath.Join(
		programData,
		fiMachineCNGKeyRelativeDir,
		uniqueName,
	)

	info, err := os.Lstat(
		path,
	)
	if err != nil {
		return "", fmt.Errorf(
			"inspect CNG machine-key file %s: %w",
			path,
			err,
		)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf(
			"CNG machine-key path %s is not a regular file",
			path,
		)
	}

	return path, nil
}

func planApproval1CNGKeyACLs(
	plan *InstallPlan,
	handoff approval1PKIHandoff,
) {
	if plan == nil {
		return
	}

	account := strings.TrimSpace(
		plan.Identities.CollectorSender.Account,
	)
	if account == "" {
		// BuildPlan owns desired-identity derivation and emits the authoritative
		// IDENTITY blocker when that derivation fails.  This handoff helper is
		// also exercised with deliberately partial synthetic plans, so it must
		// not invent a second ACL blocker merely because those plans omit the
		// already-derived identity structure.
		return
	}

	for _, item := range []struct {
		certificateSHA256 string
		role              string
		target            string
	}{
		{
			certificateSHA256: handoff.BatchCertificateSHA256,
			role:              "batch-signing",
			target: approval2BatchCNGKeyTarget(
				handoff.BatchCertificateSHA256,
			),
		},
		{
			certificateSHA256: handoff.TransportCertificateSHA256,
			role:              "transport",
			target: approval2TransportCNGKeyTarget(
				handoff.TransportCertificateSHA256,
			),
		},
	} {
		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionReconcile,
				Authority: "ACL",
				Detail: fmt.Sprintf(
					"after Approval 2 grant %s Read-only use of the exact %s CNG machine private key for certificate SHA256=%s while preserving the existing key DACL",
					account,
					item.role,
					item.certificateSHA256,
				),
				Target: item.target,
			},
		)
	}
}

func planCNGKeyACLs(
	plan *InstallPlan,
	report Report,
) {
	if plan == nil ||
		report.Trust.Presence != presencePresent {
		return
	}

	contracts := []struct {
		certificateSHA256 string
		check             string
		target            string
	}{
		{
			certificateSHA256: report.Trust.BatchSigningCertificateSHA256,
			check:             "FI batch-signing CNG key desired ACL contract",
			target: approval2BatchCNGKeyTarget(
				report.Trust.BatchSigningCertificateSHA256,
			),
		},
		{
			certificateSHA256: report.Trust.TransportCertificateSHA256,
			check:             "FI transport CNG key desired ACL contract",
			target: approval2TransportCNGKeyTarget(
				report.Trust.TransportCertificateSHA256,
			),
		},
	}

	for _, contract := range contracts {
		if !validSHA256Hex(
			contract.certificateSHA256,
		) {
			plan.Actions = append(
				plan.Actions,
				PlanAction{
					Action:    planActionBlocked,
					Authority: "ACL",
					Detail:    "exact certificate SHA-256 required for CNG private-key ACL planning is unavailable",
					Target:    contract.target,
				},
			)
			continue
		}

		state, found := findCheck(
			report,
			contract.check,
		)
		if found && state.Status == checkPass {
			plan.Actions = append(
				plan.Actions,
				PlanAction{
					Action:    planActionNoChange,
					Authority: "ACL",
					Detail:    state.Detail,
					Target:    contract.target,
				},
			)
			continue
		}

		detail := "desired CNG private-key Read-only access is not currently proven"
		if found && strings.TrimSpace(
			state.Detail,
		) != "" {
			detail = state.Detail
		}

		plan.Actions = append(
			plan.Actions,
			PlanAction{
				Action:    planActionReconcile,
				Authority: "ACL",
				Detail:    detail,
				Target:    contract.target,
			},
		)
	}
}

func readCNGKeyUniqueName(
	locator cngKeyLocator,
) (string, error) {
	if err := validateCNGKeyLocator(
		locator,
	); err != nil {
		return "", err
	}

	providerPointer, err := syscall.UTF16PtrFromString(
		locator.ProviderName,
	)
	if err != nil {
		return "", fmt.Errorf(
			"encode CNG provider name: %w",
			err,
		)
	}

	keyPointer, err := syscall.UTF16PtrFromString(
		locator.KeyName,
	)
	if err != nil {
		return "", fmt.Errorf(
			"encode CNG key name: %w",
			err,
		)
	}

	propertyPointer, err := syscall.UTF16PtrFromString(
		cngUniqueNamePropertyName,
	)
	if err != nil {
		return "", fmt.Errorf(
			"encode CNG unique-name property: %w",
			err,
		)
	}

	var provider uintptr

	status, _, _ := ncryptOpenStorageProviderPKIProc.Call(
		uintptr(
			unsafe.Pointer(
				&provider,
			),
		),
		uintptr(
			unsafe.Pointer(
				providerPointer,
			),
		),
		0,
	)

	runtime.KeepAlive(
		providerPointer,
	)

	if status != 0 {
		return "", fmt.Errorf(
			"NCryptOpenStorageProvider(%s): status=0x%08X",
			locator.ProviderName,
			uint32(status),
		)
	}
	defer ncryptFreeObjectPKIProc.Call(
		provider,
	)

	var key uintptr
	openFlags := ncryptSilentFlag
	if locator.MachineKey {
		openFlags |= ncryptMachineKeyFlag
	}

	status, _, _ = ncryptOpenKeyPKIProc.Call(
		provider,
		uintptr(
			unsafe.Pointer(
				&key,
			),
		),
		uintptr(
			unsafe.Pointer(
				keyPointer,
			),
		),
		uintptr(locator.KeySpec),
		uintptr(openFlags),
	)

	runtime.KeepAlive(
		keyPointer,
	)

	if status != 0 {
		return "", fmt.Errorf(
			"NCryptOpenKey(%s): status=0x%08X",
			locator.KeyName,
			uint32(status),
		)
	}
	defer ncryptFreeObjectPKIProc.Call(
		key,
	)

	// The unique-name property is a provider-defined UTF-16 string.  It is
	// bounded here so a corrupt or hostile provider cannot force an unbounded
	// allocation before the path is validated.
	buffer := make(
		[]uint16,
		1024,
	)
	var written uint32

	status, _, _ = ncryptGetPropertyPKIProc.Call(
		key,
		uintptr(
			unsafe.Pointer(
				propertyPointer,
			),
		),
		uintptr(
			unsafe.Pointer(
				&buffer[0],
			),
		),
		uintptr(len(buffer)*2),
		uintptr(
			unsafe.Pointer(
				&written,
			),
		),
		0,
	)

	runtime.KeepAlive(
		propertyPointer,
	)

	if status != 0 {
		return "", fmt.Errorf(
			"NCryptGetProperty(%s): status=0x%08X",
			cngUniqueNamePropertyName,
			uint32(status),
		)
	}
	if written < 2 || written > uint32(len(buffer)*2) || written%2 != 0 {
		return "", fmt.Errorf(
			"CNG unique-name property returned invalid written byte size=%d",
			written,
		)
	}

	return strings.TrimSpace(
		windows.UTF16ToString(
			buffer[:written/2],
		),
	), nil
}

func reconcileServer2016CNGKeyACLs(
	plan InstallPlan,
) ([]cngKeyACLMutation, error) {
	targets, err := cngKeyACLTargetsFromPlan(
		plan,
	)
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, nil
	}

	account := strings.TrimSpace(
		plan.Identities.CollectorSender.Account,
	)
	if account == "" {
		return nil, errors.New(
			"collector/sender gMSA identity is unavailable for CNG private-key ACL reconciliation",
		)
	}

	accountSID, err :=
		authoritativeDesiredFIIdentitySID(
			plan.Identities.CollectorSender,
		)
	if err != nil {
		return nil, fmt.Errorf(
			"revalidate sealed collector/sender gMSA SID for CNG private-key ACL: %w",
			err,
		)
	}

	mutations := make(
		[]cngKeyACLMutation,
		0,
		len(targets),
	)

	rollback := func() error {
		return restoreCNGKeyACLMutations(
			mutations,
		)
	}

	fail := func(
		base error,
	) ([]cngKeyACLMutation, error) {
		if rollbackErr := rollback(); rollbackErr != nil {
			base = errors.Join(
				base,
				fmt.Errorf(
					"rollback CNG key ACL mutations: %w",
					rollbackErr,
				),
			)
		}

		return nil, base
	}

	for _, target := range targets {
		path, err := machineCNGKeyFilePathForCertificateSHA256(
			target.CertificateSHA256,
		)
		if err != nil {
			return fail(
				fmt.Errorf(
					"resolve %s file: %w",
					target.Label,
					err,
				),
			)
		}

		state, err := discoverACL(
			path,
			target.Label,
		)
		if err != nil {
			return fail(
				err,
			)
		}

		if cngKeyACLHasReadOnly(
			state,
			account,
		) {
			continue
		}

		if entry, found := cngKeyACLHasForbiddenAllow(
			state,
			account,
		); found {
			return fail(
				fmt.Errorf(
					"%s ACL grants forbidden rights to %s mask=0x%08X; refusing to append Read over an overprivileged existing ALLOW ACE",
					target.Label,
					account,
					entry.Mask,
				),
			)
		}

		previous, err := captureNamedSecurityDescriptorSDDL(
			path,
		)
		if err != nil {
			return fail(
				err,
			)
		}

		desired, err := appendCNGKeyReadACE(
			previous,
			accountSID.String(),
		)
		if err != nil {
			return fail(
				err,
			)
		}

		// Take rollback ownership before attempting the write.  If Windows
		// reports an error after partially changing the DACL, the original
		// descriptor is still restored.
		mutations = append(
			mutations,
			cngKeyACLMutation{
				Path:         path,
				PreviousSDDL: previous,
			},
		)

		if err := setNamedDACLFromSDDL(
			path,
			desired,
		); err != nil {
			return fail(
				err,
			)
		}

		verified, err := discoverACL(
			path,
			target.Label,
		)
		if err != nil {
			return fail(
				err,
			)
		}
		if !cngKeyACLHasReadOnly(
			verified,
			account,
		) {
			return fail(
				fmt.Errorf(
					"%s ACL mutation did not grant Read-only access to %s",
					target.Label,
					account,
				),
			)
		}
	}

	return mutations, nil
}
func restoreCNGKeyACLMutations(
	mutations []cngKeyACLMutation,
) error {
	var found []error

	for index := len(mutations) - 1; index >= 0; index-- {
		mutation := mutations[index]
		if err := setNamedDACLFromSDDL(
			mutation.Path,
			mutation.PreviousSDDL,
		); err != nil {
			found = append(
				found,
				fmt.Errorf(
					"restore CNG key DACL %s: %w",
					mutation.Path,
					err,
				),
			)
		}
	}

	return errors.Join(
		found...,
	)
}

func setNamedDACLFromSDDL(
	path string,
	sddl string,
) error {
	descriptor, err := windows.SecurityDescriptorFromString(
		sddl,
	)
	if err != nil {
		return fmt.Errorf(
			"parse desired DACL SDDL for %s: %w",
			path,
			err,
		)
	}

	dacl, _, err := descriptor.DACL()
	if err != nil {
		return fmt.Errorf(
			"read desired DACL for %s: %w",
			path,
			err,
		)
	}
	if dacl == nil {
		return fmt.Errorf(
			"desired DACL for %s is null",
			path,
		)
	}

	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	); err != nil {
		return fmt.Errorf(
			"apply desired DACL to %s: %w",
			path,
			err,
		)
	}

	return nil
}

func validCNGKeyUniqueName(
	value string,
) bool {
	value = strings.TrimSpace(
		value,
	)
	if value == "" ||
		value == "." ||
		value == ".." ||
		filepath.Base(value) != value ||
		strings.ContainsAny(
			value,
			`/\\`,
		) {
		return false
	}

	return true
}
