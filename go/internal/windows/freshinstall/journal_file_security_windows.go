// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package freshinstall

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// verifyCreationJournalFileHandle inspects security on the NEWLY CREATED
// retained file handle. No named-path lookup is permitted. An unacceptable
// effective DACL is a failed/in-doubt creation, never automatic rollback or
// another CREATE_NEW attempt. The handle's type and parent identity must
// already have been independently checked by ReserveNew.
func verifyCreationJournalFileHandle(handle windows.Handle) error {
	if handle == 0 || handle == windows.InvalidHandle {
		return fmt.Errorf("%w: missing journal file handle", ErrUntrustedJournalFile)
	}
	observed, err := inspectJournalParentSecurityByHandle(handle)
	if err != nil {
		return fmt.Errorf("%w: inspect journal file owner/DACL: %v", ErrUntrustedJournalFile, err)
	}
	if err := ValidateCreationJournalFileSecurity(observed); err != nil {
		return err
	}
	return nil
}
