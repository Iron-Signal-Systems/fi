// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"errors"
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

func joinACLMutationRollbackFailure(
	base error,
	rollback func() error,
) error {
	if base == nil {
		base = errors.New(
			"ACL mutation failed",
		)
	}

	if rollback == nil {
		return base
	}

	if rollbackErr := rollback(); rollbackErr != nil {
		return errors.Join(
			base,
			fmt.Errorf(
				"rollback FI ACL mutations: %w",
				rollbackErr,
			),
		)
	}

	return base
}

func reconcileServer2016ACLs(report Report, identities DesiredFIIdentities, plan InstallPlan) (func() error, error) {
	collectorSID, err :=
		authoritativeDesiredFIIdentitySID(
			identities.CollectorSender,
		)
	if err != nil {
		return nil, err
	}

	crlSID, err :=
		authoritativeDesiredFIIdentitySID(
			identities.CRLRefresher,
		)
	if err != nil {
		return nil, err
	}

	usnSID, err :=
		authoritativeDesiredFIIdentitySID(
			identities.USNReader,
		)
	if err != nil {
		return nil, err
	}

	objSID, err :=
		authoritativeDesiredFIIdentitySID(
			identities.ObjReader,
		)
	if err != nil {
		return nil, err
	}

	type contract struct {
		path                string
		sddl                string
		target              string
		useRestorePrivilege bool
	}
	readOnlyServices := desiredProtectedDirectorySDDL([]sddlACE{
		{Mask: fileReadExecuteMask, SID: collectorSID.String()},
		{Mask: fileReadExecuteMask, SID: crlSID.String()},
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

	pkiCRL := desiredProtectedDirectorySDDL([]sddlACE{
		{Mask: fileReadExecuteMask, SID: collectorSID.String()},
		{Mask: fileModifyMask, SID: crlSID.String()},
	})

	activeCRL := desiredProtectedObjectSDDL([]sddlACE{
		{Mask: fileReadExecuteMask, SID: collectorSID.String()},
		{Mask: fileModifyMask, SID: crlSID.String()},
	})

	journalDirectory := desiredProtectedObjectSDDL([]sddlACE{
		{Mask: fileReadExecuteMask, SID: crlSID.String()},
	})

	journalFile := desiredProtectedObjectSDDL([]sddlACE{
		{Mask: crlRefresherJournalMask, SID: crlSID.String()},
	})

	trustConfigFile := desiredProtectedObjectSDDL([]sddlACE{
		{Mask: fileReadExecuteMask, SID: collectorSID.String()},
		{Mask: fileReadExecuteMask, SID: usnSID.String()},
		{Mask: fileReadExecuteMask, SID: objSID.String()},
		{Mask: fileReadExecuteMask, SID: crlSID.String()},
	})

	crlExecutable := desiredProtectedObjectSDDL([]sddlACE{
		{Mask: fileReadExecuteMask, SID: crlSID.String()},
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
		{
			path: spoolParentDirectoryTarget(
				report.Config.SpoolDir,
			),
			target: spoolParentDirectoryTarget(
				report.Config.SpoolDir,
			),
		},
		{
			path: generationRawDirectoryTarget(
				report.Config.SpoolDir,
			),
			sddl: writableCollector,
			target: generationRawDirectoryTarget(
				report.Config.SpoolDir,
			),
		},
		{
			path: collectorWorkDirectoryTarget(
				report.Config.SpoolDir,
			),
			sddl: writableCollector,
			target: collectorWorkDirectoryTarget(
				report.Config.SpoolDir,
			),
		},
		{path: report.Config.StageDir, sddl: writableCollector, target: valueOrNotKnown(report.Config.StageDir)},
	}
	if legacyTransportTrustDirectoryRequired(
		report,
	) {
		contracts = append(
			contracts,
			contract{
				path: filepath.Dir(
					report.Trust.TransportCRLPath,
				),
				sddl:   readOnlyCollector,
				target: "FI PKI trust root",
			},
		)
	}

	contracts = append(
		contracts,
		contract{
			path:   crlRefresherActivationDirectory,
			sddl:   pkiCRL,
			target: crlRefresherActivationDirectory,
		},
		contract{
			path:   approval1TransportCRLDestination,
			sddl:   activeCRL,
			target: approval1TransportCRLDestination,
		},
		contract{
			path:   crlRefresherJournalDirectory,
			sddl:   journalDirectory,
			target: crlRefresherJournalDirectory,
		},
		contract{
			path:   crlRefresherJournalPath,
			sddl:   journalFile,
			target: crlRefresherJournalPath,
		},
		contract{
			path:   crlRefresherTrustConfigPath,
			sddl:   trustConfigFile,
			target: crlRefresherTrustConfigPath,
		},
		contract{
			path:   crlRefresherExecutablePath,
			sddl:   crlExecutable,
			target: crlRefresherExecutablePath,
		},
	)

	seen := make(map[string]struct{})
	mutations := make([]aclMutation, 0, len(contracts))

	rollbackMutations := func() error {
		return rollbackACLMutations(
			mutations,
		)
	}

	for _, item := range contracts {
		if !planTargetMutates(plan, "ACL", item.target) {
			continue
		}
		path := filepath.Clean(strings.TrimSpace(item.path))
		if path == "" || path == "." {
			return nil, joinACLMutationRollbackFailure(
				fmt.Errorf(
					"refusing to reconcile an empty ACL path",
				),
				rollbackMutations,
			)
		}
		key := strings.ToLower(path)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		previous, err := captureNamedSecurityDescriptorSDDL(path)
		if err != nil {
			return nil, joinACLMutationRollbackFailure(
				err,
				rollbackMutations,
			)
		}
		// Take rollback ownership before the native security-descriptor write.
		// Windows may partially change the descriptor before returning an error.
		mutations = append(
			mutations,
			aclMutation{
				Path:         path,
				PreviousSDDL: previous,
			},
		)

		apply := func() error {
			if strings.EqualFold(
				item.target,
				spoolParentDirectoryTarget(report.Config.SpoolDir),
			) {
				return grantSpoolParentSenderAccess(
					path,
					collectorSID,
				)
			}

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
			return nil, joinACLMutationRollbackFailure(
				err,
				rollbackMutations,
			)
		}
	}

	cngMutations, err := reconcileServer2016CNGKeyACLs(
		plan,
	)
	if err != nil {
		return nil, errors.Join(
			err,
			rollbackACLMutations(
				mutations,
			),
		)
	}

	if err := verifyServer2016ACLMutations(
		report,
		plan,
	); err != nil {
		return nil, errors.Join(
			err,
			restoreCNGKeyACLMutations(
				cngMutations,
			),
			rollbackACLMutations(
				mutations,
			),
		)
	}

	return func() error {
		return errors.Join(
			restoreCNGKeyACLMutations(
				cngMutations,
			),
			rollbackACLMutations(
				mutations,
			),
		)
	}, nil
}

func aclVerificationReport(
	report Report,
) Report {
	return Report{
		Config:   report.Config,
		Host:     report.Host,
		Join:     report.Join,
		Services: report.Services,
		Trust:    report.Trust,
	}
}

func aliasACLStateForVerification(
	report *Report,
	sourceLabel string,
	aliasLabel string,
	expectedPath string,
) {
	aliasACLStateForSemanticContract(
		report,
		sourceLabel,
		aliasLabel,
		expectedPath,
	)
}

func evaluateServer2016ACLVerificationContracts(
	report *Report,
) {
	aliasACLStateForVerification(
		report,
		"FI transport trust config",
		"FI CRL refresher trust config file",
		crlRefresherTrustConfigPath,
	)

	evaluateDesiredACLContracts(
		report,
	)
}
func verifyServer2016ACLMutations(
	report Report,
	plan InstallPlan,
) error {
	verification :=
		aclVerificationReport(
			report,
		)

	if !discoverACLStates(
		&verification,
	) {
		return fmt.Errorf(
			"ACL mutation verification could not establish physical ACL discovery state",
		)
	}

	evaluateServer2016ACLVerificationContracts(
		&verification,
	)

	verificationPlan :=
		InstallPlan{}

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
