// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"

	"github.com/Iron-Signal-Systems/fi/go/internal/windows/freshinstall"
)

// rejectDisabledReadOnlySelectors runs immediately after parsing flags and
// before any legacy installer operation. A caller who explicitly selects a
// read-only flag with =false must NOT silently fall into default -apply=true.
func rejectDisabledReadOnlySelectors(flags *flag.FlagSet) error {
	if flags == nil {
		return errors.New("FI installer flags are required")
	}
	var rejected []string
	flags.Visit(func(item *flag.Flag) {
		switch item.Name {
		case "check-clean-install", "list-volumes", "inspect-policy-roots":
			if item.Value.String() != "true" {
				rejected = append(rejected, "-"+item.Name)
			}
		}
	})
	if len(rejected) != 0 {
		sort.Strings(rejected)
		return fmt.Errorf("explicit read-only selector disabled; refusing legacy apply fallback: %v", rejected)
	}
	return nil
}

// freshInstallCLI ensures the read-only check never accidentally falls
// through to the old installer's default -apply=true path. Explicitly given
// flags are rejected even when they repeat their default value.
func freshInstallCLI(flags *flag.FlagSet) error {
	if flags == nil {
		return errors.New("FI new-install flag set required")
	}
	if flags.NArg() != 0 {
		return errors.New("-check-clean-install does not accept positional arguments")
	}
	var conflicts []string
	flags.Visit(func(item *flag.Flag) {
		if item.Name != "check-clean-install" {
			conflicts = append(conflicts, "-"+item.Name)
		}
	})
	if len(conflicts) > 0 {
		sort.Strings(conflicts)
		return fmt.Errorf("-check-clean-install is a standalone read-only action; conflicting flags: %v", conflicts)
	}
	return nil
}

// writeFreshInstallPreflight reports all observed FI collisions before
// returning the blocker error. A report showing Clean=true is a point-in-time
// observation only, NOT signed installer consent or permission to mutate.
func writeFreshInstallPreflight(output io.Writer, inspector freshinstall.Inspector) error {
	if output == nil {
		return errors.New("FI preflight output is required")
	}
	report, checkErr := freshinstall.Assess(inspector)
	if checkErr != nil && !errors.Is(checkErr, freshinstall.ErrExistingFI) {
		return fmt.Errorf("inspect local FI installation state: %w", checkErr)
	}
	enc := json.NewEncoder(output)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		return fmt.Errorf("write FI new-install preflight report: %w", err)
	}
	return checkErr
}

// runNativeFreshInstallPreflight performs ONLY read-only local checks. A
// future version-2 installer must repeat the check at its actual write
// boundary; this CLI cannot grant authority or perform any installation.
func runNativeFreshInstallPreflight(output io.Writer) error {
	inspector, err := freshinstall.OpenNativeInspector()
	if err != nil {
		return err
	}
	reportErr := writeFreshInstallPreflight(output, inspector)
	if closeErr := inspector.Close(); closeErr != nil {
		return fmt.Errorf("release FI preflight SCM connection: %w", closeErr)
	}
	return reportErr
}
