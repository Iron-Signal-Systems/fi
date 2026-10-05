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
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

type ACLEntry struct {
	Account   string
	Flags     uint8
	Inherited bool
	Mask      uint32
	SID       string
	Type      string
}

type ACLState struct {
	Entries   []ACLEntry
	Label     string
	Owner     string
	Path      string
	Protected bool
}

type aclTarget struct {
	Label string
	Path  string
}

const ownerRightsSID = "S-1-3-4"

func aclTargetAbsenceRepairable(
	label string,
) bool {
	switch label {
	case "FI CRL activation directory",
		"FI CRL active file",
		"FI CRL refresher executable file",
		"FI CRL refresher journal directory",
		"FI CRL refresher journal file",
		"FI CRL refresher trust config file":
		return true

	default:
		return false
	}
}

func aclDiscoveryFailureStatus(
	label string,
	err error,
) string {
	if !aclTargetAbsenceRepairable(
		label,
	) {
		return checkFail
	}

	if errors.Is(
		err,
		os.ErrNotExist,
	) ||
		errors.Is(
			err,
			windows.ERROR_FILE_NOT_FOUND,
		) ||
		errors.Is(
			err,
			windows.ERROR_PATH_NOT_FOUND,
		) {
		return checkInfo
	}

	return checkFail
}
func aceTypeName(value uint8) string {
	switch value {
	case windows.ACCESS_ALLOWED_ACE_TYPE:
		return "ALLOW"
	case windows.ACCESS_DENIED_ACE_TYPE:
		return "DENY"
	default:
		return fmt.Sprintf("ACE-%d", value)
	}
}

func accountNameForSID(sid *windows.SID) string {
	if sid == nil {
		return notKnown
	}

	account, domain, _, err := sid.LookupAccount("")
	if err != nil {
		return sid.String()
	}
	if strings.TrimSpace(domain) == "" {
		return account
	}
	return domain + `\` + account
}

func discoverACL(path string, label string) (ACLState, error) {
	state := ACLState{
		Label: label,
		Path:  path,
	}

	descriptor, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|
			windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return state, fmt.Errorf(
			"read DACL for %s: %w",
			path,
			err,
		)
	}
	if descriptor == nil {
		return state, fmt.Errorf(
			"read DACL for %s: security descriptor is nil",
			path,
		)
	}

	owner, _, err := descriptor.Owner()
	if err != nil {
		return state, fmt.Errorf(
			"read owner for %s: %w",
			path,
			err,
		)
	}
	state.Owner = accountNameForSID(owner)

	control, _, err := descriptor.Control()
	if err != nil {
		return state, fmt.Errorf(
			"read security-descriptor control for %s: %w",
			path,
			err,
		)
	}
	state.Protected = control&windows.SE_DACL_PROTECTED != 0

	dacl, _, err := descriptor.DACL()
	if err != nil {
		if errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) {
			return state, fmt.Errorf(
				"%s has no DACL",
				path,
			)
		}
		return state, fmt.Errorf(
			"read DACL entries for %s: %w",
			path,
			err,
		)
	}
	if dacl == nil {
		return state, fmt.Errorf(
			"%s has a null DACL",
			path,
		)
	}

	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(
			dacl,
			uint32(index),
			&ace,
		); err != nil {
			return state, fmt.Errorf(
				"read ACE %d for %s: %w",
				index,
				path,
				err,
			)
		}
		if ace == nil {
			return state, fmt.Errorf(
				"read ACE %d for %s: ACE is nil",
				index,
				path,
			)
		}

		entry := ACLEntry{
			Flags:     ace.Header.AceFlags,
			Inherited: ace.Header.AceFlags&windows.INHERITED_ACE != 0,
			Mask:      uint32(ace.Mask),
			SID:       notKnown,
			Type:      aceTypeName(ace.Header.AceType),
		}

		switch ace.Header.AceType {
		case windows.ACCESS_ALLOWED_ACE_TYPE,
			windows.ACCESS_DENIED_ACE_TYPE:
			sid := (*windows.SID)(
				unsafe.Pointer(&ace.SidStart),
			)
			entry.SID = sid.String()
			entry.Account = accountNameForSID(sid)
		default:
			entry.Account = notKnown
		}

		state.Entries = append(state.Entries, entry)
	}

	return state, nil
}

func plannedACLTargets(
	report Report,
) []aclTarget {
	targets := []aclTarget{
		{
			Label: "FI config directory",
			Path:  filepath.Dir(report.Config.Path),
		},
		{
			Label: "FI state directory",
			Path:  report.Config.StateDir,
		},
		{
			Label: "FI spool directory",
			Path:  report.Config.SpoolDir,
		},
		{
			Label: "FI stage directory",
			Path:  report.Config.StageDir,
		},
		{
			Label: "FI program directory",
			Path:  `C:\Program Files\FI`,
		},
		{
			Label: "FI CRL activation directory",
			Path:  crlRefresherActivationDirectory,
		},
		{
			Label: "FI CRL refresher journal directory",
			Path:  crlRefresherJournalDirectory,
		},
		{
			Label: "FI CRL refresher journal file",
			Path:  crlRefresherJournalPath,
		},
		{
			Label: "FI CRL refresher trust config file",
			Path:  crlRefresherTrustConfigPath,
		},
		{
			Label: "FI CRL refresher executable file",
			Path:  crlRefresherExecutablePath,
		},
		{
			Label: "FI CRL active file",
			Path:  approval1TransportCRLDestination,
		},
	}

	if report.ReleaseTrust.Installed.Present {
		targets = append(
			targets,
			aclTarget{
				Label: "FI release trust directory",
				Path:  installedReleaseTrustRoot,
			},
		)
	}

	if legacyTransportTrustDirectoryRequired(
		report,
	) {
		targets = append(
			targets,
			aclTarget{
				Label: "FI PKI trust directory",
				Path: filepath.Dir(
					report.Trust.TransportCRLPath,
				),
			},
		)
	}

	return targets
}

func desiredACLAccounts(
	report Report,
) (
	string,
	string,
	string,
	string,
	error,
) {
	identities, err := DeriveDesiredFIIdentities(
		report.Host.Computer,
		report.Join.Name,
	)
	if err != nil {
		return "", "", "", "", err
	}

	return identities.CollectorSender.Account,
		identities.CRLRefresher.Account,
		identities.USNReader.Account,
		identities.ObjReader.Account,
		nil
}

// supplementACLDiscoveryForPlan performs read-only DACL discovery when the
// operational FI configuration is absent but planConfiguration has already
// populated the proposed authoritative deployment paths.
//
// This is intentionally a planning supplement rather than inferred state:
// every ACL decision is still based on a native security-descriptor read from
// the exact path the operator supplied or an FI fixed/retained trust root.
//
// Missing SCM registrations do not suppress this discovery. Desired FI
// identities are derived from the domain-joined host identity.
func supplementACLDiscoveryForPlan(
	report *Report,
) {
	if report == nil {
		return
	}

	if report.Config.Presence != presenceAbsent {
		return
	}

	// Before planConfiguration runs, these values are not authoritative.
	// Do not guess paths from filesystem contents.
	if strings.TrimSpace(
		report.Config.Path,
	) == "" ||
		strings.TrimSpace(
			report.Config.SpoolDir,
		) == "" ||
		strings.TrimSpace(
			report.Config.StageDir,
		) == "" ||
		strings.TrimSpace(
			report.Config.StateDir,
		) == "" {
		return
	}

	if _, found := findCheck(
		*report,
		"FI DACL planning supplement",
	); found {
		return
	}

	collector, crlRefresher, usnReader, objReader, err :=
		desiredACLAccounts(
			*report,
		)
	if err != nil {
		report.addCheck(
			checkFail,
			"FI DACL planning supplement",
			fmt.Sprintf(
				"derive desired FI identities for ACL discovery: %v",
				err,
			),
		)
		return
	}

	seen := make(
		map[string]struct{},
	)

	for _, target := range plannedACLTargets(
		*report,
	) {
		path := strings.TrimSpace(
			target.Path,
		)

		if path == "" {
			report.addCheck(
				checkFail,
				target.Label+" DACL",
				"path is unavailable",
			)
			continue
		}

		key := strings.ToLower(
			filepath.Clean(
				path,
			),
		)

		if _, ok := seen[key]; ok {
			continue
		}

		seen[key] = struct{}{}

		state, err := discoverACL(
			path,
			target.Label,
		)
		if err != nil {
			report.addCheck(
				aclDiscoveryFailureStatus(
					target.Label,
					err,
				),
				target.Label+" DACL",
				err.Error(),
			)
			continue
		}

		report.ACLs = append(
			report.ACLs,
			state,
		)

		report.addCheck(
			checkPass,
			target.Label+" DACL",
			fmt.Sprintf(
				"path=%s owner=%s protected=%t entries=%d",
				state.Path,
				state.Owner,
				state.Protected,
				len(state.Entries),
			),
		)

		for _, entry := range state.Entries {
			if entry.Type != "ALLOW" {
				continue
			}

			if !isBroadPrincipal(
				entry.SID,
			) {
				continue
			}

			if !maskIncludesWriteOrACLAdministration(
				entry.Mask,
			) {
				continue
			}

			report.addCheck(
				checkWarn,
				target.Label+" broad write access",
				fmt.Sprintf(
					"account=%s sid=%s mask=0x%08X inherited=%t",
					entry.Account,
					entry.SID,
					entry.Mask,
					entry.Inherited,
				),
			)
		}
	}

	evaluateDesiredACLContractsForAccounts(
		report,
		collector,
		crlRefresher,
		usnReader,
		objReader,
	)

	report.addCheck(
		checkInfo,
		"FI DACL planning supplement",
		"read-only DACL discovery used the proposed operational paths and retained FI trust roots independently of SCM service presence",
	)
}
func discoverACLs(report *Report) {
	if report.Config.Presence == presenceAbsent {
		report.addCheck(
			checkInfo,
			"FI DACL discovery",
			"operational configuration is absent; FI-owned ACL roots will be planned from the proposed new-install configuration",
		)
		return
	}
	if report.Config.Presence == presenceUnknown {
		report.addCheck(
			checkFail,
			"FI DACL discovery",
			"operational configuration presence is unknown",
		)
		return
	}
	if strings.TrimSpace(report.Config.Path) == "" {
		report.addCheck(
			checkFail,
			"FI DACL discovery",
			"operational configuration path is unavailable",
		)
		return
	}

	targets := []aclTarget{
		{
			Label: "FI config directory",
			Path:  filepath.Dir(report.Config.Path),
		},
		{
			Label: "FI operational config",
			Path:  report.Config.Path,
		},
		{
			Label: "FI transport trust config",
			Path:  report.Trust.Path,
		},
		{
			Label: "FI state directory",
			Path:  report.Config.StateDir,
		},
		{
			Label: "FI spool directory",
			Path:  report.Config.SpoolDir,
		},
		{
			Label: "FI stage directory",
			Path:  report.Config.StageDir,
		},
		{
			Label: "FI program directory",
			Path:  `C:\Program Files\FI`,
		},
		{
			Label: "FI CRL activation directory",
			Path:  crlRefresherActivationDirectory,
		},
		{
			Label: "FI CRL refresher journal directory",
			Path:  crlRefresherJournalDirectory,
		},
		{
			Label: "FI CRL refresher journal file",
			Path:  crlRefresherJournalPath,
		},
		{
			Label: "FI CRL refresher trust config file",
			Path:  crlRefresherTrustConfigPath,
		},
		{
			Label: "FI CRL refresher executable file",
			Path:  crlRefresherExecutablePath,
		},
		{
			Label: "FI CRL active file",
			Path:  approval1TransportCRLDestination,
		},
	}

	if info, err := os.Stat(installedReleaseTrustRoot); err == nil && info.IsDir() {
		targets = append(
			targets,
			aclTarget{
				Label: "FI release trust directory",
				Path:  installedReleaseTrustRoot,
			},
		)
	}

	if strings.TrimSpace(report.Trust.TransportCRLPath) != "" {
		targets = append(
			targets,
			aclTarget{
				Label: "FI PKI trust directory",
				Path:  filepath.Dir(report.Trust.TransportCRLPath),
			},
		)
	}

	seen := make(map[string]struct{})

	for _, target := range targets {
		path := strings.TrimSpace(target.Path)
		if path == "" {
			report.addCheck(
				checkFail,
				target.Label+" DACL",
				"path is unavailable",
			)
			continue
		}

		key := strings.ToLower(filepath.Clean(path))
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		state, err := discoverACL(path, target.Label)
		if err != nil {
			report.addCheck(
				aclDiscoveryFailureStatus(
					target.Label,
					err,
				),
				target.Label+" DACL",
				err.Error(),
			)
			continue
		}

		report.ACLs = append(report.ACLs, state)
		report.addCheck(
			checkPass,
			target.Label+" DACL",
			fmt.Sprintf(
				"path=%s owner=%s protected=%t entries=%d",
				state.Path,
				state.Owner,
				state.Protected,
				len(state.Entries),
			),
		)

		for _, entry := range state.Entries {
			if entry.Type != "ALLOW" {
				continue
			}
			if !isBroadPrincipal(entry.SID) {
				continue
			}
			if !maskIncludesWriteOrACLAdministration(entry.Mask) {
				continue
			}

			report.addCheck(
				checkWarn,
				target.Label+" broad write access",
				fmt.Sprintf(
					"account=%s sid=%s mask=0x%08X inherited=%t",
					entry.Account,
					entry.SID,
					entry.Mask,
					entry.Inherited,
				),
			)
		}
	}
	evaluateDesiredACLContracts(report)
}

func isBroadPrincipal(sidText string) bool {
	switch sidText {
	case "S-1-1-0": // Everyone
		return true
	case "S-1-5-32-545": // BUILTIN\Users
		return true
	default:
		return false
	}
}

func maskIncludesWriteOrACLAdministration(mask uint32) bool {
	dangerous := uint32(
		windows.FILE_WRITE_DATA |
			windows.FILE_APPEND_DATA |
			windows.FILE_WRITE_EA |
			windows.FILE_WRITE_ATTRIBUTES |
			windows.DELETE |
			windows.WRITE_DAC |
			windows.WRITE_OWNER,
	)

	return mask&dangerous != 0
}

const (
	fileFullControlMask = uint32(0x001F01FF)
	fileModifyMask      = uint32(0x001301BF)
	fileReadExecuteMask = uint32(0x001200A9)
)

func aclByLabel(report *Report, label string) (ACLState, bool) {
	for _, state := range report.ACLs {
		if state.Label == label {
			return state, true
		}
	}
	return ACLState{}, false
}

func serviceAccount(report *Report, name string) string {
	for _, service := range report.Services {
		if service.Name == name {
			return service.Account
		}
	}
	return ""
}

func accountMatches(entry ACLEntry, account string) bool {
	return strings.EqualFold(
		strings.TrimSpace(entry.Account),
		strings.TrimSpace(account),
	)
}

func allowedAccount(account string, allowed []string) bool {
	for _, current := range allowed {
		if strings.EqualFold(
			strings.TrimSpace(account),
			strings.TrimSpace(current),
		) {
			return true
		}
	}
	return false
}

func hasAllowMask(
	state ACLState,
	account string,
	required uint32,
	forbidden uint32,
) bool {
	for _, entry := range state.Entries {
		if entry.Type != "ALLOW" || !accountMatches(entry, account) {
			continue
		}
		if entry.Mask&required != required {
			continue
		}
		if forbidden != 0 && entry.Mask&forbidden != 0 {
			continue
		}
		return true
	}
	return false
}

func hasAllowMaskSID(
	state ACLState,
	sid string,
	required uint32,
	forbidden uint32,
) bool {
	for _, entry := range state.Entries {
		if entry.Type != "ALLOW" ||
			!strings.EqualFold(
				strings.TrimSpace(
					entry.SID,
				),
				strings.TrimSpace(
					sid,
				),
			) {
			continue
		}
		if entry.Mask&required != required {
			continue
		}
		if forbidden != 0 &&
			entry.Mask&forbidden != 0 {
			continue
		}
		return true
	}
	return false
}

func hasUnexpectedAllowPrincipal(
	state ACLState,
	allowed []string,
) (ACLEntry, bool) {
	for _, entry := range state.Entries {
		if entry.Type != "ALLOW" {
			continue
		}
		if allowedAccount(entry.Account, allowed) {
			continue
		}
		return entry, true
	}
	return ACLEntry{}, false
}

func isAdministrativeOwner(owner string) bool {
	return strings.EqualFold(owner, `BUILTIN\Administrators`) ||
		strings.EqualFold(owner, `NT AUTHORITY\SYSTEM`)
}

func evaluateReadOnlyRoot(
	report *Report,
	label string,
	requireProtected bool,
	requiredReaders []string,
) {
	state, ok := aclByLabel(report, label)
	if !ok {
		report.addCheck(
			checkFail,
			label+" desired ACL contract",
			"DACL state was not discovered",
		)
		return
	}

	var failures []string

	if !isAdministrativeOwner(state.Owner) {
		failures = append(
			failures,
			"owner="+state.Owner+" expected Administrators or SYSTEM",
		)
	}
	if requireProtected && !state.Protected {
		failures = append(
			failures,
			"DACL inheritance is enabled",
		)
	}

	allowed := []string{
		`BUILTIN\Administrators`,
		`NT AUTHORITY\SYSTEM`,
	}
	allowed = append(allowed, requiredReaders...)

	if unexpected, found := hasUnexpectedAllowPrincipal(
		state,
		allowed,
	); found {
		failures = append(
			failures,
			fmt.Sprintf(
				"unexpected allow principal %s mask=0x%08X",
				unexpected.Account,
				unexpected.Mask,
			),
		)
	}

	if !hasAllowMask(
		state,
		`BUILTIN\Administrators`,
		fileFullControlMask,
		0,
	) {
		failures = append(
			failures,
			"Administrators FullControl missing",
		)
	}
	if !hasAllowMask(
		state,
		`NT AUTHORITY\SYSTEM`,
		fileFullControlMask,
		0,
	) {
		failures = append(
			failures,
			"SYSTEM FullControl missing",
		)
	}

	for _, account := range requiredReaders {
		if strings.TrimSpace(account) == "" {
			failures = append(
				failures,
				"required service identity unavailable",
			)
			continue
		}
		forbidden := uint32(
			windows.FILE_WRITE_DATA |
				windows.FILE_APPEND_DATA |
				windows.WRITE_DAC |
				windows.WRITE_OWNER,
		)
		if !hasAllowMask(
			state,
			account,
			fileReadExecuteMask,
			forbidden,
		) {
			failures = append(
				failures,
				account+" Read/Execute without write/ACL administration missing",
			)
		}
	}

	if len(failures) != 0 {
		report.addCheck(
			checkFail,
			label+" desired ACL contract",
			strings.Join(failures, "; "),
		)
		return
	}

	report.addCheck(
		checkPass,
		label+" desired ACL contract",
		"administrative ownership; required service read/execute; no unexpected allow principals",
	)
}

func evaluateWritableRoot(
	report *Report,
	label string,
	requireProtected bool,
	ownerMustBeAdministrative bool,
	collector string,
) {
	state, ok := aclByLabel(report, label)
	if !ok {
		report.addCheck(
			checkFail,
			label+" desired ACL contract",
			"DACL state was not discovered",
		)
		return
	}

	var failures []string

	if ownerMustBeAdministrative && !isAdministrativeOwner(state.Owner) {
		failures = append(
			failures,
			"owner="+state.Owner+" expected Administrators or SYSTEM",
		)
	}
	if requireProtected && !state.Protected {
		failures = append(
			failures,
			"DACL inheritance is enabled",
		)
	}

	allowed := []string{
		`BUILTIN\Administrators`,
		`NT AUTHORITY\SYSTEM`,
		collector,
	}
	if unexpected, found := hasUnexpectedAllowPrincipal(
		state,
		allowed,
	); found {
		failures = append(
			failures,
			fmt.Sprintf(
				"unexpected allow principal %s mask=0x%08X",
				unexpected.Account,
				unexpected.Mask,
			),
		)
	}

	if !hasAllowMask(
		state,
		`BUILTIN\Administrators`,
		fileFullControlMask,
		0,
	) {
		failures = append(
			failures,
			"Administrators FullControl missing",
		)
	}
	if !hasAllowMask(
		state,
		`NT AUTHORITY\SYSTEM`,
		fileFullControlMask,
		0,
	) {
		failures = append(
			failures,
			"SYSTEM FullControl missing",
		)
	}

	aclAdministration := uint32(
		windows.WRITE_DAC |
			windows.WRITE_OWNER,
	)

	if strings.TrimSpace(collector) == "" {
		failures = append(
			failures,
			"collector/sender identity unavailable",
		)
	} else if !hasAllowMask(
		state,
		collector,
		fileModifyMask,
		aclAdministration,
	) {
		failures = append(
			failures,
			collector+" Modify without WRITE_DAC/WRITE_OWNER missing",
		)
	}

	for _, entry := range state.Entries {
		if entry.Type != "ALLOW" ||
			!accountMatches(entry, collector) {
			continue
		}
		if entry.Mask&aclAdministration != 0 {
			failures = append(
				failures,
				fmt.Sprintf(
					"%s has ACL-administration rights mask=0x%08X",
					collector,
					entry.Mask,
				),
			)
		}
	}

	if len(failures) != 0 {
		report.addCheck(
			checkFail,
			label+" desired ACL contract",
			strings.Join(failures, "; "),
		)
		return
	}

	report.addCheck(
		checkPass,
		label+" desired ACL contract",
		"Administrators/SYSTEM FullControl; collector/sender Modify without ACL administration; no unexpected allow principals",
	)
}

func evaluateSpoolRoot(
	report *Report,
	collector string,
) {
	state, ok := aclByLabel(
		report,
		"FI spool directory",
	)
	if !ok {
		report.addCheck(
			checkFail,
			"FI spool directory desired ACL contract",
			"DACL state was not discovered",
		)
		return
	}

	var failures []string

	if strings.TrimSpace(
		collector,
	) == "" {
		failures = append(
			failures,
			"collector/sender identity unavailable",
		)
	} else if !strings.EqualFold(
		strings.TrimSpace(
			state.Owner,
		),
		strings.TrimSpace(
			collector,
		),
	) {
		failures = append(
			failures,
			fmt.Sprintf(
				"owner=%s expected rotating-spool owner %s",
				state.Owner,
				collector,
			),
		)
	}

	if !state.Protected {
		failures = append(
			failures,
			"DACL inheritance is enabled",
		)
	}

	for _, entry := range state.Entries {
		if entry.Type != "ALLOW" {
			continue
		}
		if accountMatches(
			entry,
			`BUILTIN\Administrators`,
		) ||
			accountMatches(
				entry,
				`NT AUTHORITY\SYSTEM`,
			) ||
			strings.EqualFold(
				entry.SID,
				ownerRightsSID,
			) {
			continue
		}
		failures = append(
			failures,
			fmt.Sprintf(
				"unexpected allow principal %s mask=0x%08X",
				entry.Account,
				entry.Mask,
			),
		)
		break
	}

	if !hasAllowMask(
		state,
		`BUILTIN\Administrators`,
		fileFullControlMask,
		0,
	) {
		failures = append(
			failures,
			"Administrators FullControl missing",
		)
	}
	if !hasAllowMask(
		state,
		`NT AUTHORITY\SYSTEM`,
		fileFullControlMask,
		0,
	) {
		failures = append(
			failures,
			"SYSTEM FullControl missing",
		)
	}

	aclAdministration := uint32(
		windows.WRITE_DAC |
			windows.WRITE_OWNER,
	)

	if !hasAllowMaskSID(
		state,
		ownerRightsSID,
		fileModifyMask,
		aclAdministration,
	) {
		failures = append(
			failures,
			"OWNER RIGHTS Modify without WRITE_DAC/WRITE_OWNER missing",
		)
	}

	for _, entry := range state.Entries {
		if entry.Type != "ALLOW" ||
			!strings.EqualFold(
				entry.SID,
				ownerRightsSID,
			) {
			continue
		}
		if entry.Mask&aclAdministration != 0 {
			failures = append(
				failures,
				fmt.Sprintf(
					"OWNER RIGHTS has ACL-administration rights mask=0x%08X",
					entry.Mask,
				),
			)
		}
	}

	if len(failures) != 0 {
		report.addCheck(
			checkFail,
			"FI spool directory desired ACL contract",
			strings.Join(
				failures,
				"; ",
			),
		)
		return
	}

	report.addCheck(
		checkPass,
		"FI spool directory desired ACL contract",
		"rotating spool owner is collector/sender; OWNER RIGHTS grants Modify but suppresses implicit WRITE_DAC/WRITE_OWNER; Administrators/SYSTEM retain FullControl; DACL is protected",
	)
}

func evaluateStageRoot(
	report *Report,
	collector string,
) {
	state, ok := aclByLabel(report, "FI stage directory")
	if !ok {
		return
	}

	var failures []string
	allowed := []string{
		`BUILTIN\Administrators`,
		`NT AUTHORITY\SYSTEM`,
		collector,
	}
	if unexpected, found := hasUnexpectedAllowPrincipal(
		state,
		allowed,
	); found {
		failures = append(
			failures,
			fmt.Sprintf(
				"unexpected allow principal %s mask=0x%08X",
				unexpected.Account,
				unexpected.Mask,
			),
		)
	}

	aclAdministration := uint32(
		windows.WRITE_DAC |
			windows.WRITE_OWNER,
	)
	if !hasAllowMask(
		state,
		collector,
		fileModifyMask,
		aclAdministration,
	) {
		failures = append(
			failures,
			collector+" Modify without ACL administration missing",
		)
	}

	if len(failures) != 0 {
		report.addCheck(
			checkFail,
			"FI stage directory desired ACL shape",
			strings.Join(failures, "; "),
		)
		return
	}

	report.addCheck(
		checkPass,
		"FI stage directory desired ACL shape",
		"Administrators/SYSTEM plus collector/sender Modify; no unexpected allow principals",
	)
	if !state.Protected {
		report.addCheck(
			checkWarn,
			"FI stage directory inheritance",
			"stage DACL currently inherits its correct shape; final installer contract should decide whether to protect the FI-owned stage root explicitly",
		)
	}
}

func evaluatePKITrustRoot(
	report *Report,
	collector string,
) {
	state, ok := aclByLabel(report, "FI PKI trust directory")
	if !ok {
		return
	}

	var failures []string

	if !isAdministrativeOwner(state.Owner) {
		failures = append(
			failures,
			"owner="+state.Owner+" expected Administrators or SYSTEM",
		)
	}
	if !state.Protected {
		failures = append(
			failures,
			"DACL inheritance is enabled",
		)
	}

	allowed := []string{
		`BUILTIN\Administrators`,
		`NT AUTHORITY\SYSTEM`,
		collector,
	}
	if unexpected, found := hasUnexpectedAllowPrincipal(
		state,
		allowed,
	); found {
		failures = append(
			failures,
			fmt.Sprintf(
				"unexpected allow principal %s mask=0x%08X",
				unexpected.Account,
				unexpected.Mask,
			),
		)
	}

	forbidden := uint32(
		windows.FILE_WRITE_DATA |
			windows.FILE_APPEND_DATA |
			windows.WRITE_DAC |
			windows.WRITE_OWNER,
	)
	if !hasAllowMask(
		state,
		collector,
		fileReadExecuteMask,
		forbidden,
	) {
		failures = append(
			failures,
			collector+" Read/Execute without write/ACL administration missing",
		)
	}

	if len(failures) != 0 {
		report.addCheck(
			checkFail,
			"FI PKI trust directory desired ACL contract",
			strings.Join(failures, "; "),
		)
		return
	}

	report.addCheck(
		checkPass,
		"FI PKI trust directory desired ACL contract",
		"administrative ownership; collector/sender read-only; no unexpected allow principals",
	)
}

func evaluateReleaseTrustRoot(report *Report) {
	state, ok := aclByLabel(report, "FI release trust directory")
	if !ok {
		return
	}

	var failures []string
	if !isAdministrativeOwner(state.Owner) {
		failures = append(failures, "owner="+state.Owner+" expected Administrators or SYSTEM")
	}
	if !state.Protected {
		failures = append(failures, "DACL inheritance is enabled")
	}
	allowed := []string{`BUILTIN\Administrators`, `NT AUTHORITY\SYSTEM`}
	if unexpected, found := hasUnexpectedAllowPrincipal(state, allowed); found {
		failures = append(failures, fmt.Sprintf("unexpected allow principal %s mask=0x%08X", unexpected.Account, unexpected.Mask))
	}
	if !hasAllowMask(state, `BUILTIN\Administrators`, fileFullControlMask, 0) {
		failures = append(failures, "Administrators FullControl missing")
	}
	if !hasAllowMask(state, `NT AUTHORITY\SYSTEM`, fileFullControlMask, 0) {
		failures = append(failures, "SYSTEM FullControl missing")
	}
	if len(failures) != 0 {
		report.addCheck(checkFail, "FI release trust directory desired ACL contract", strings.Join(failures, "; "))
		return
	}
	report.addCheck(checkPass, "FI release trust directory desired ACL contract", "protected administrative-only release-trust state")
}

func evaluateDesiredACLContracts(report *Report) {
	if report == nil {
		return
	}

	_, crlRefresher, _, _, err :=
		desiredACLAccounts(
			*report,
		)
	if err != nil {
		report.addCheck(
			checkFail,
			"FI desired ACL identities",
			fmt.Sprintf(
				"derive desired FI identities for ACL evaluation: %v",
				err,
			),
		)
		return
	}

	evaluateDesiredACLContractsForAccounts(
		report,
		serviceAccount(
			report,
			"FICollector",
		),
		crlRefresher,
		serviceAccount(
			report,
			"FIUSNReader",
		),
		serviceAccount(
			report,
			"FIObjReader",
		),
	)

	evaluateCRLRefresherACLContracts(
		report,
	)
}

func evaluateDesiredACLContractsForAccounts(
	report *Report,
	collector string,
	crlRefresher string,
	usnReader string,
	objReader string,
) {
	evaluateReadOnlyRoot(
		report,
		"FI config directory",
		true,
		[]string{
			collector,
			crlRefresher,
			usnReader,
			objReader,
		},
	)

	evaluateReadOnlyRoot(
		report,
		"FI program directory",
		true,
		[]string{
			collector,
			crlRefresher,
			usnReader,
			objReader,
		},
	)

	evaluateWritableRoot(
		report,
		"FI state directory",
		true,
		true,
		collector,
	)

	evaluateSpoolRoot(
		report,
		collector,
	)

	evaluateStageRoot(
		report,
		collector,
	)

	evaluatePKITrustRoot(
		report,
		collector,
	)

	evaluateReleaseTrustRoot(
		report,
	)
}
