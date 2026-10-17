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
	"unsafe"

	"golang.org/x/sys/windows"
)

const spoolParentSenderMask = fileReadExecuteMask | uint32(0x00000004)

// grantSpoolParentSenderAccess merges one non-inheritable sender ACE.
// It does not replace the parent owner or its existing DACL entries.
func grantSpoolParentSenderAccess(
	path string,
	senderSID *windows.SID,
) error {
	if senderSID == nil || !senderSID.IsValid() {
		return errors.New("valid sender SID required")
	}

	path = filepath.Clean(strings.TrimSpace(path))

	if !filepath.IsAbs(path) ||
		filepath.Dir(path) == path {
		return fmt.Errorf(
			"refusing unsafe FI spool parent path %q",
			path,
		)
	}

	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf(
			"inspect FI spool parent: %w",
			err,
		)
	}

	if info.Mode()&os.ModeSymlink != 0 ||
		!info.IsDir() {
		return errors.New(
			"FI spool parent must be a real directory",
		)
	}

	observed, err := discoverACL(
		path,
		spoolParentDirectoryACLLabel,
	)
	if err != nil {
		return err
	}

	for _, entry := range observed.Entries {
		if strings.EqualFold(entry.SID, senderSID.String()) {
			return fmt.Errorf(
				"FI spool parent already has sender ACE; refusing ambiguous ACL merge",
			)
		}
	}

	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf(
			"read FI spool parent DACL: %w",
			err,
		)
	}

	if sd == nil {
		return errors.New("FI spool parent descriptor is nil")
	}

	existing, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("read existing DACL: %w", err)
	}
	if existing == nil {
		return errors.New("refusing null parent DACL")
	}

	control, _, err := sd.Control()
	if err != nil {
		return fmt.Errorf("read DACL control: %w", err)
	}

	entries := []windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: windows.ACCESS_MASK(
				spoolParentSenderMask,
			),
			AccessMode:  windows.GRANT_ACCESS,
			Inheritance: windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm: windows.TRUSTEE_IS_SID,
				TrusteeType: windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValue(
					unsafe.Pointer(senderSID),
				),
			},
		},
	}

	merged, err := windows.ACLFromEntries(
		entries,
		existing,
	)
	runtime.KeepAlive(senderSID)

	if err != nil {
		return fmt.Errorf(
			"merge FI sender parent ACE: %w",
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

	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|inheritance,
		nil,
		nil,
		merged,
		nil,
	); err != nil {
		return fmt.Errorf(
			"apply FI spool parent sender ACE: %w",
			err,
		)
	}

	return nil
}
