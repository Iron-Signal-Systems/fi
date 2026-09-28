// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

type aclMutation struct {
	Path         string
	PreviousSDDL string
}

type sddlACE struct {
	Mask uint32
	SID  string
}

func reconcileServer2016ACLs(report Report, identities DesiredFIIdentities, plan InstallPlan) (func() error, error) {
	collectorSID, collectorBuffer, err := lookupAccountSID(identities.CollectorSender.Account)
	if err != nil {
		return nil, err
	}
	_ = collectorBuffer
	usnSID, usnBuffer, err := lookupAccountSID(identities.USNReader.Account)
	if err != nil {
		return nil, err
	}
	_ = usnBuffer
	objSID, objBuffer, err := lookupAccountSID(identities.ObjReader.Account)
	if err != nil {
		return nil, err
	}
	_ = objBuffer

	type contract struct {
		path                string
		sddl                string
		target              string
		useRestorePrivilege bool
	}
	readOnlyServices := desiredProtectedDirectorySDDL([]sddlACE{
		{Mask: fileReadExecuteMask, SID: collectorSID.String()},
		{Mask: fileReadExecuteMask, SID: usnSID.String()},
		{Mask: fileReadExecuteMask, SID: objSID.String()},
	})
	writableCollector := desiredProtectedDirectorySDDL([]sddlACE{
		{Mask: fileModifyMask, SID: collectorSID.String()},
	})
	rotatingSpool := desiredProtectedSpoolSDDL(
		collectorSID.String(),
	)
	readOnlyCollector := desiredProtectedDirectorySDDL([]sddlACE{
		{Mask: fileReadExecuteMask, SID: collectorSID.String()},
	})

	contracts := []contract{
		{path: filepath.Dir(report.Config.Path), sddl: readOnlyServices, target: `C:\ProgramData\FI\config`},
		{path: `C:\Program Files\FI`, sddl: readOnlyServices, target: `C:\Program Files\FI`},
		{path: report.Config.StateDir, sddl: writableCollector, target: valueOrNotKnown(report.Config.StateDir)},
		{
			path:                report.Config.SpoolDir,
			sddl:                rotatingSpool,
			target:              valueOrNotKnown(report.Config.SpoolDir),
			useRestorePrivilege: true,
		},
		{path: report.Config.StageDir, sddl: writableCollector, target: valueOrNotKnown(report.Config.StageDir)},
	}
	if strings.TrimSpace(report.Trust.TransportCRLPath) != "" {
		contracts = append(contracts, contract{
			path:   filepath.Dir(report.Trust.TransportCRLPath),
			sddl:   readOnlyCollector,
			target: "FI PKI trust root",
		})
	}

	seen := make(map[string]struct{})
	mutations := make([]aclMutation, 0, len(contracts))
	for _, item := range contracts {
		if !planTargetMutates(plan, "ACL", item.target) {
			continue
		}
		path := filepath.Clean(strings.TrimSpace(item.path))
		if path == "" || path == "." {
			_ = rollbackACLMutations(mutations)
			return nil, fmt.Errorf("refusing to reconcile an empty ACL path")
		}
		key := strings.ToLower(path)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		previous, err := captureNamedSecurityDescriptorSDDL(path)
		if err != nil {
			_ = rollbackACLMutations(mutations)
			return nil, err
		}
		apply := func() error {
			return setNamedSecurityDescriptorFromSDDL(
				path,
				item.sddl,
			)
		}
		if item.useRestorePrivilege {
			err = withEnabledProcessPrivilege(
				"SeRestorePrivilege",
				apply,
			)
		} else {
			err = apply()
		}
		if err != nil {
			_ = rollbackACLMutations(
				mutations,
			)
			return nil, err
		}
		mutations = append(
			mutations,
			aclMutation{
				Path:         path,
				PreviousSDDL: previous,
			},
		)
	}

	if err := verifyServer2016ACLMutations(
		report,
		plan,
	); err != nil {
		_ = rollbackACLMutations(
			mutations,
		)
		return nil, err
	}

	return func() error {
		return rollbackACLMutations(
			mutations,
		)
	}, nil
}

func verifyServer2016ACLMutations(
	report Report,
	plan InstallPlan,
) error {
	verification := Report{
		Config:   report.Config,
		Services: report.Services,
		Trust:    report.Trust,
	}
	discoverACLs(
		&verification,
	)

	verificationPlan := InstallPlan{}
	planACLs(
		&verificationPlan,
		verification,
	)

	var remaining []string
	for _, action := range verificationPlan.Actions {
		if action.Authority != "ACL" ||
			!planActionMutates(
				action.Action,
			) ||
			!planTargetMutates(
				plan,
				"ACL",
				action.Target,
			) {
			continue
		}
		remaining = append(
			remaining,
			fmt.Sprintf(
				"%s: %s",
				action.Target,
				action.Detail,
			),
		)
	}
	if len(remaining) != 0 {
		return fmt.Errorf(
			"ACL mutation did not converge before later installation phases: %s",
			strings.Join(
				remaining,
				"; ",
			),
		)
	}
	return nil
}

func planTargetMutates(plan InstallPlan, authority string, target string) bool {
	for _, action := range plan.Actions {
		if action.Authority == authority &&
			strings.EqualFold(strings.TrimSpace(action.Target), strings.TrimSpace(target)) &&
			planActionMutates(action.Action) {
			return true
		}
	}
	return false
}

func desiredProtectedSpoolSDDL(
	ownerSID string,
) string {
	return fmt.Sprintf(
		"O:%sD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;0x%08X;;;OW)",
		ownerSID,
		fileModifyMask,
	)
}

func desiredProtectedDirectorySDDL(entries []sddlACE) string {
	var builder strings.Builder
	builder.WriteString("O:BAD:P")
	builder.WriteString("(A;OICI;FA;;;BA)")
	builder.WriteString("(A;OICI;FA;;;SY)")
	for _, entry := range entries {
		fmt.Fprintf(&builder, "(A;OICI;0x%08X;;;%s)", entry.Mask, entry.SID)
	}
	return builder.String()
}

func captureNamedSecurityDescriptorSDDL(path string) (string, error) {
	descriptor, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return "", fmt.Errorf("capture security descriptor for %s: %w", path, err)
	}
	if descriptor == nil {
		return "", fmt.Errorf("capture security descriptor for %s: descriptor is nil", path)
	}
	sddl := descriptor.String()
	if strings.TrimSpace(sddl) == "" {
		return "", fmt.Errorf("capture security descriptor for %s: SDDL conversion returned an empty value", path)
	}
	return sddl, nil
}

func setNamedSecurityDescriptorFromSDDL(path string, sddl string) error {
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("parse desired SDDL for %s: %w", path, err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return fmt.Errorf("read desired owner for %s: %w", path, err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return fmt.Errorf("read desired DACL for %s: %w", path, err)
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return fmt.Errorf("read desired DACL control for %s: %w", path, err)
	}
	inheritance := windows.SECURITY_INFORMATION(
		windows.UNPROTECTED_DACL_SECURITY_INFORMATION,
	)
	if control&windows.SE_DACL_PROTECTED != 0 {
		inheritance = windows.SECURITY_INFORMATION(
			windows.PROTECTED_DACL_SECURITY_INFORMATION,
		)
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|inheritance,
		owner,
		nil,
		dacl,
		nil,
	); err != nil {
		return fmt.Errorf("apply desired security descriptor to %s: %w", path, err)
	}
	return nil
}

func restoreNamedSecurityDescriptorFromSDDL(
	path string,
	sddl string,
) error {
	descriptor, err := windows.SecurityDescriptorFromString(
		sddl,
	)
	if err != nil {
		return fmt.Errorf(
			"parse rollback SDDL for %s: %w",
			path,
			err,
		)
	}

	owner, _, err := descriptor.Owner()
	if err != nil {
		return fmt.Errorf(
			"read rollback owner for %s: %w",
			path,
			err,
		)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return fmt.Errorf(
			"read rollback DACL for %s: %w",
			path,
			err,
		)
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return fmt.Errorf(
			"read rollback DACL control for %s: %w",
			path,
			err,
		)
	}

	inheritance := windows.SECURITY_INFORMATION(
		windows.UNPROTECTED_DACL_SECURITY_INFORMATION,
	)
	if control&windows.SE_DACL_PROTECTED != 0 {
		inheritance = windows.SECURITY_INFORMATION(
			windows.PROTECTED_DACL_SECURITY_INFORMATION,
		)
	}

	// Restore the DACL and inheritance state independently from ownership.
	// This avoids losing the ACL rollback when Windows rejects an arbitrary
	// previous owner SID without SeRestorePrivilege.
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|
			inheritance,
		nil,
		nil,
		dacl,
		nil,
	); err != nil {
		return fmt.Errorf(
			"restore DACL for %s: %w",
			path,
			err,
		)
	}

	// A previous owner can legitimately be a service identity. Microsoft
	// documents SeRestorePrivilege as the authority that permits assigning
	// any valid user/group SID as owner. Enable it only for this narrow call,
	// then restore the original process-token privilege state.
	if owner != nil {
		if err := withEnabledProcessPrivilege(
			"SeRestorePrivilege",
			func() error {
				if err := windows.SetNamedSecurityInfo(
					path,
					windows.SE_FILE_OBJECT,
					windows.OWNER_SECURITY_INFORMATION,
					owner,
					nil,
					nil,
					nil,
				); err != nil {
					return fmt.Errorf(
						"restore owner for %s: %w",
						path,
						err,
					)
				}
				return nil
			},
		); err != nil {
			return err
		}
	}

	return nil
}

func rollbackACLMutations(
	mutations []aclMutation,
) error {
	var first error
	for index := len(mutations) - 1; index >= 0; index-- {
		if err := restoreNamedSecurityDescriptorFromSDDL(
			mutations[index].Path,
			mutations[index].PreviousSDDL,
		); err != nil && first == nil {
			first = err
		}
	}
	return first
}
