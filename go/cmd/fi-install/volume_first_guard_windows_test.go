// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"errors"
	"testing"
)

// This gate is examined before any native discovery, PKI trust prompt,
// SACL recovery, SCM operation, or legacy installer planning in main.
func TestVolumeFirstInstallerRejectsAllLegacyApplyAndPlanModes(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"-apply"},
		{"-apply=false"},
		{"-plan-only"},
		{"-plan-only=false"},
		{"-apply", "-plan-only"},
		{"-config=C:\\FI\\old.conf"},
		{"-volume-config=C:\\FI\\volume-v2.conf"},
		{"-inspect-policy-roots"},
		{"-check-clean-install=false"},
		{"-list-volumes=false"},
		{"-inspect-policy-roots=false"},
		{"-check-clean-install", "-list-volumes"},
		{"-list-volumes", "-check-clean-install"},
		{"-check-clean-install", "-apply=false"},
		{"-list-volumes", "-volume-config=C:\\FI\\volume-v2.conf", "-apply=false"},
		{"-list-volumes", "-volume-config=C:\\FI\\volume-v2.conf", "-plan-only"},
		{"-list-volumes", "-inspect-policy-roots"},
		{"-check-clean-install", "-config=C:\\FI\\legacy.conf"},
		{"-list-volumes", "-check-clean-install=false"},
		{"-check-clean-install", "-inspect-policy-roots=false"},
		{"-list-volumes", "unexpected-positional-input"},
	} {
		if err := requireVolumeFirstReadOnlyMode(freshFlags(t, args...)); !errors.Is(err, ErrVolumeFirstApplyUnavailable) {
			t.Fatalf("legacy installer path not blocked for %v: %v", args, err)
		}
	}
	if err := requireVolumeFirstReadOnlyMode(nil); !errors.Is(err, ErrVolumeFirstApplyUnavailable) {
		t.Fatalf("nil flag set must block before legacy installation: %v", err)
	}
}

func TestVolumeFirstInstallerAllowsOnlyStandaloneReadOnlyActions(t *testing.T) {
	for _, args := range [][]string{
		{"-check-clean-install"},
		{"-check-clean-install=true"},
		{"-list-volumes"},
		{"-list-volumes=true"},
		{"-list-volumes", "-volume-config=C:\\FI\\volume-v2.conf"},
		{"-list-volumes", "-volume-config=C:\\FI\\volume-v2.conf", "-inspect-policy-roots"},
	} {
		if err := requireVolumeFirstReadOnlyMode(freshFlags(t, args...)); err != nil {
			t.Fatalf("safe diagnostic action %v rejected: %v", args, err)
		}
	}
}
