// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestResolveLocalGroupNameUsesWellKnownBuiltinSID(
	t *testing.T,
) {
	for _, test := range []struct {
		label string
		sid   string
	}{
		{
			label: "Administrators",
			sid:   localAdministratorsSID,
		},
		{
			label: "Backup Operators",
			sid:   localBackupOperatorsSID,
		},
		{
			label: "Event Log Readers",
			sid:   localEventLogReadersSID,
		},
	} {
		t.Run(
			test.label,
			func(t *testing.T) {
				sid, err := windows.StringToSid(
					test.sid,
				)
				if err != nil {
					t.Fatal(err)
				}

				want, _, _, err := sid.LookupAccount(
					"",
				)
				if err != nil {
					t.Fatal(err)
				}

				got, err := resolveLocalGroupName(
					test.label,
				)
				if err != nil {
					t.Fatal(err)
				}

				if !strings.EqualFold(
					got,
					want,
				) {
					t.Fatalf(
						"resolved group=%q want=%q SID=%s",
						got,
						want,
						test.sid,
					)
				}
			},
		)
	}
}

func TestResolveLocalGroupNamePreservesNonBuiltinGroup(
	t *testing.T,
) {
	t.Parallel()

	const group = "FI Custom Operators"

	got, err := resolveLocalGroupName(
		group,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got != group {
		t.Fatalf(
			"resolved group=%q want=%q",
			got,
			group,
		)
	}
}

func TestResolveLocalGroupNameRejectsEmptyName(
	t *testing.T,
) {
	t.Parallel()

	if _, err := resolveLocalGroupName(
		" ",
	); err == nil {
		t.Fatal(
			"empty local group name unexpectedly accepted",
		)
	}
}
