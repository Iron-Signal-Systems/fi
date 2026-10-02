// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows"
)

const (
	localAdministratorsSID  = "S-1-5-32-544"
	localBackupOperatorsSID = "S-1-5-32-551"
	localEventLogReadersSID = "S-1-5-32-573"
)

var builtinLocalGroupSIDs = map[string]string{
	"administrators":    localAdministratorsSID,
	"backup operators":  localBackupOperatorsSID,
	"event log readers": localEventLogReadersSID,
}

// resolveLocalGroupName converts FI's canonical built-in-group labels to the
// actual localized group name on the current Windows host.
//
// FI keeps stable English labels in plans and records. Native NetAPI calls,
// however, must use the host's actual localized local-group name.
func resolveLocalGroupName(
	group string,
) (string, error) {
	group = strings.TrimSpace(
		group,
	)
	if group == "" {
		return "", fmt.Errorf(
			"local group name is required",
		)
	}

	sidText, builtin := builtinLocalGroupSIDs[strings.ToLower(
		group,
	)]
	if !builtin {
		return group, nil
	}

	sid, err := windows.StringToSid(
		sidText,
	)
	if err != nil {
		return "", fmt.Errorf(
			"parse built-in group SID %s for %s: %w",
			sidText,
			group,
			err,
		)
	}

	account, _, _, err := sid.LookupAccount(
		"",
	)
	if err != nil {
		return "", fmt.Errorf(
			"resolve built-in group %s SID=%s: %w",
			group,
			sidText,
			err,
		)
	}

	account = strings.TrimSpace(
		account,
	)
	if account == "" {
		return "", fmt.Errorf(
			"resolve built-in group %s SID=%s returned an empty local name",
			group,
			sidText,
		)
	}

	return account, nil
}
