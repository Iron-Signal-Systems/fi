// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import "testing"

func TestValidateApplyPKIChoice(
	t *testing.T,
) {
	tests := []struct {
		choice  string
		wantErr bool
	}{
		{
			choice: "",
		},
		{
			choice: "enroll",
		},
		{
			choice: "ENROLL",
		},
		{
			choice:  "reuse",
			wantErr: true,
		},
		{
			choice:  "create",
			wantErr: true,
		},
		{
			choice:  "bogus",
			wantErr: true,
		},
	}

	for _, test := range tests {
		err :=
			validateApplyPKIChoice(
				test.choice,
			)

		if test.wantErr &&
			err == nil {
			t.Fatalf(
				"choice=%q unexpectedly accepted",
				test.choice,
			)
		}

		if !test.wantErr &&
			err != nil {
			t.Fatalf(
				"choice=%q unexpectedly rejected: %v",
				test.choice,
				err,
			)
		}
	}
}
