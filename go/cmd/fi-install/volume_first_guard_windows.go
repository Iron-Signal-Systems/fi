// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"errors"
	"flag"
	"fmt"
)

// ErrVolumeFirstApplyUnavailable indicates that this development branch has
// NOT implemented a complete, approved fresh-install v2 transaction. This is
// intentionally distinct from a host failing the read-only clean-host check.
var ErrVolumeFirstApplyUnavailable = errors.New("FI v2 fresh installation is not implemented; this development build is diagnostics-only")

// requireVolumeFirstReadOnlyMode is the earliest post-Parse installer gate.
// The inherited FI 1.1 installer defaults to -apply=true; until the v2
// replacement is complete, the old default is not safe for a clean-volume
// installation and MUST NOT remain reachable by any combination of flags.
//
// Only the two explicitly selected read-only operations are allowed. Each
// operation independently validates all supplied flags before a filesystem,
// service, PKI or domain operation can begin. A disabled selector, legacy
// plan-only mode, an empty invocation and an old installer argument are all
// rejected without falling through to the existing 1.1 apply path.
//
// This boundary does NOT create or authorize any v2 installation. It must
// eventually be replaced only by a separately reviewed fresh-only installer,
// never by relaxing this guard to restore legacy mutation.
func requireVolumeFirstReadOnlyMode(flags *flag.FlagSet) error {
	if flags == nil {
		return fmt.Errorf("%w: no parsed installer arguments", ErrVolumeFirstApplyUnavailable)
	}
	var clean, inventory bool
	flags.Visit(func(item *flag.Flag) {
		switch item.Name {
		case "check-clean-install":
			clean = item.Value.String() == "true"
		case "list-volumes":
			inventory = item.Value.String() == "true"
		}
	})
	if clean && inventory {
		return fmt.Errorf("%w: multiple standalone diagnostic actions selected", ErrVolumeFirstApplyUnavailable)
	}
	if clean {
		if err := freshInstallCLI(flags); err != nil {
			return fmt.Errorf("%w: %v", ErrVolumeFirstApplyUnavailable, err)
		}
		return nil
	}
	if inventory {
		if err := volumeInventoryCLI(flags); err != nil {
			return fmt.Errorf("%w: %v", ErrVolumeFirstApplyUnavailable, err)
		}
		return nil
	}
	return ErrVolumeFirstApplyUnavailable
}
