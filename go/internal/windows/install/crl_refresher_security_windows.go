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

	"golang.org/x/sys/windows"
)

const (
	crlRefresherActivationDirectory = `C:\ProgramData\FI\pki\crl`

	crlRefresherExecutablePath = `C:\Program Files\FI\fi-crl-refresh.exe`

	crlRefresherJournalDirectory = `C:\ProgramData\FI\crl-refresh`

	crlRefresherJournalPath = `C:\ProgramData\FI\crl-refresh\crl-refresh.jsonl`

	crlRefresherTrustConfigPath = `C:\ProgramData\FI\config\fi-transport-trust.conf`
)

var crlRefresherJournalMask = uint32(
	windows.FILE_APPEND_DATA |
		windows.FILE_READ_ATTRIBUTES |
		windows.SYNCHRONIZE,
)

func desiredProtectedObjectSDDL(
	entries []sddlACE,
) string {
	var builder strings.Builder

	builder.WriteString(
		"O:BAD:P",
	)

	builder.WriteString(
		"(A;;FA;;;BA)",
	)

	builder.WriteString(
		"(A;;FA;;;SY)",
	)

	for _, entry := range entries {
		fmt.Fprintf(
			&builder,
			"(A;;0x%08X;;;%s)",
			entry.Mask,
			entry.SID,
		)
	}

	return builder.String()
}

func evaluateCRLRefresherACLContracts(
	report *Report,
) {
	if report == nil {
		return
	}

	_, refresher, _, _, err :=
		desiredACLAccounts(
			*report,
		)
	if err != nil {
		report.addCheck(
			checkFail,
			"FI CRL refresher desired ACL identity",
			"derive desired FI identities: "+err.Error(),
		)
		return
	}

	collector :=
		serviceAccount(
			report,
			"FICollector",
		)

	usnReader :=
		serviceAccount(
			report,
			"FIUSNReader",
		)

	objReader :=
		serviceAccount(
			report,
			"FIObjReader",
		)

	evaluateExactProtectedACL(
		report,
		"FI CRL activation directory",
		map[string]uint32{
			collector: fileReadExecuteMask,
			refresher: fileModifyMask,
		},
	)

	evaluateExactProtectedACL(
		report,
		"FI CRL refresher journal directory",
		map[string]uint32{
			refresher: fileReadExecuteMask,
		},
	)

	evaluateExactProtectedACL(
		report,
		"FI CRL refresher journal file",
		map[string]uint32{
			refresher: crlRefresherJournalMask,
		},
	)

	evaluateExactProtectedACL(
		report,
		"FI CRL refresher trust config file",
		map[string]uint32{
			collector: fileReadExecuteMask,
			usnReader: fileReadExecuteMask,
			objReader: fileReadExecuteMask,
			refresher: fileReadExecuteMask,
		},
	)

	evaluateExactProtectedACL(
		report,
		"FI CRL refresher executable file",
		map[string]uint32{
			refresher: fileReadExecuteMask,
		},
	)

	evaluateExactProtectedACL(
		report,
		"FI CRL active file",
		map[string]uint32{
			collector: fileReadExecuteMask,
			refresher: fileModifyMask,
		},
	)
}

func evaluateExactProtectedACL(
	report *Report,
	label string,
	expected map[string]uint32,
) {
	state, ok :=
		aclByLabel(
			report,
			label,
		)
	if !ok {
		return
	}

	var failures []string

	if !isAdministrativeOwner(
		state.Owner,
	) {
		failures =
			append(
				failures,
				"owner="+state.Owner+" expected Administrators or SYSTEM",
			)
	}

	if !state.Protected {
		failures =
			append(
				failures,
				"DACL inheritance is enabled",
			)
	}

	allowed :=
		[]string{
			`BUILTIN\Administrators`,
			`NT AUTHORITY\SYSTEM`,
		}

	for account := range expected {
		if strings.TrimSpace(
			account,
		) == "" {
			failures =
				append(
					failures,
					"required service identity unavailable",
				)

			continue
		}

		allowed =
			append(
				allowed,
				account,
			)
	}

	if unexpected, found :=
		hasUnexpectedAllowPrincipal(
			state,
			allowed,
		); found {
		failures =
			append(
				failures,
				fmt.Sprintf(
					"unexpected allow principal %s mask=0x%08X",
					unexpected.Account,
					unexpected.Mask,
				),
			)
	}

	for account, mask := range expected {
		if strings.TrimSpace(
			account,
		) == "" {
			continue
		}

		if !hasExactAllowMask(
			state,
			account,
			mask,
		) {
			failures =
				append(
					failures,
					fmt.Sprintf(
						"%s exact allow mask missing want=0x%08X",
						account,
						mask,
					),
				)
		}
	}

	if !hasExactAllowMask(
		state,
		`BUILTIN\Administrators`,
		fileFullControlMask,
	) {
		failures =
			append(
				failures,
				"Administrators FullControl missing",
			)
	}

	if !hasExactAllowMask(
		state,
		`NT AUTHORITY\SYSTEM`,
		fileFullControlMask,
	) {
		failures =
			append(
				failures,
				"SYSTEM FullControl missing",
			)
	}

	if len(
		failures,
	) != 0 {
		report.addCheck(
			checkFail,
			label+" desired ACL contract",
			strings.Join(
				failures,
				"; ",
			),
		)

		return
	}

	report.addCheck(
		checkPass,
		label+" desired ACL contract",
		"protected exact least-privilege ACL contract",
	)
}

func hasExactAllowMask(
	state ACLState,
	account string,
	expected uint32,
) bool {
	for _, entry := range state.Entries {
		if entry.Type !=
			"ALLOW" {
			continue
		}

		if !accountMatches(
			entry,
			account,
		) {
			continue
		}

		if entry.Mask ==
			expected {
			return true
		}
	}

	return false
}

func prepareCRLRefresherSecurityFilesystem() (
	func() error,
	error,
) {
	crlDirectory :=
		filepath.Dir(
			approval1TransportCRLDestination,
		)

	createdDirectories, err :=
		prepareApproval2OwnedDirectories(
			[]string{
				crlDirectory,
				crlRefresherJournalDirectory,
			},
		)
	if err != nil {
		return nil, err
	}

	rollbackDirectories :=
		func() error {
			return rollbackApproval2CreatedDirectories(
				createdDirectories,
			)
		}

	journalCreated := false

	info, err :=
		os.Lstat(
			crlRefresherJournalPath,
		)

	switch {
	case err == nil:
		if info.Mode()&
			os.ModeSymlink != 0 {
			return nil, errors.Join(
				fmt.Errorf(
					"CRL refresh journal must not be a symbolic link: %s",
					crlRefresherJournalPath,
				),
				rollbackDirectories(),
			)
		}

		if !info.Mode().
			IsRegular() {
			return nil, errors.Join(
				fmt.Errorf(
					"CRL refresh journal must be a regular file: %s",
					crlRefresherJournalPath,
				),
				rollbackDirectories(),
			)
		}

	case errors.Is(
		err,
		os.ErrNotExist,
	):
		file, createErr :=
			os.OpenFile(
				crlRefresherJournalPath,
				os.O_CREATE|
					os.O_EXCL|
					os.O_WRONLY,
				0o600,
			)
		if createErr != nil {
			return nil, errors.Join(
				fmt.Errorf(
					"create CRL refresh journal: %w",
					createErr,
				),
				rollbackDirectories(),
			)
		}

		if syncErr :=
			file.Sync(); syncErr != nil {
			_ =
				file.Close()

			_ =
				os.Remove(
					crlRefresherJournalPath,
				)

			return nil, errors.Join(
				fmt.Errorf(
					"sync new CRL refresh journal: %w",
					syncErr,
				),
				rollbackDirectories(),
			)
		}

		if closeErr :=
			file.Close(); closeErr != nil {
			_ =
				os.Remove(
					crlRefresherJournalPath,
				)

			return nil, errors.Join(
				fmt.Errorf(
					"close new CRL refresh journal: %w",
					closeErr,
				),
				rollbackDirectories(),
			)
		}

		journalCreated = true

		if err :=
			setNamedSecurityDescriptorFromSDDL(
				crlRefresherJournalPath,
				desiredProtectedObjectSDDL(
					nil,
				),
			); err != nil {
			_ =
				os.Remove(
					crlRefresherJournalPath,
				)

			return nil, errors.Join(
				fmt.Errorf(
					"protect new CRL refresh journal: %w",
					err,
				),
				rollbackDirectories(),
			)
		}

	default:
		return nil, errors.Join(
			fmt.Errorf(
				"inspect CRL refresh journal: %w",
				err,
			),
			rollbackDirectories(),
		)
	}

	return func() error {
		var found []error

		if journalCreated {
			if err :=
				os.Remove(
					crlRefresherJournalPath,
				); err != nil &&
				!errors.Is(
					err,
					os.ErrNotExist,
				) {
				found =
					append(
						found,
						fmt.Errorf(
							"remove transaction-created CRL refresh journal: %w",
							err,
						),
					)
			}
		}

		if err :=
			rollbackDirectories(); err != nil {
			found =
				append(
					found,
					err,
				)
		}

		return errors.Join(
			found...,
		)
	}, nil
}
