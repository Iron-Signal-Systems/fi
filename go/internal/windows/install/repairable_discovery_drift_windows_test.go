// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows"
)

func TestACLDiscoveryFailureStatus(
	t *testing.T,
) {
	t.Parallel()

	tests := []struct {
		err   error
		label string
		want  string
	}{
		{
			err:   windows.ERROR_FILE_NOT_FOUND,
			label: "FI CRL active file",
			want:  checkInfo,
		},
		{
			err:   windows.ERROR_PATH_NOT_FOUND,
			label: "FI CRL refresher journal directory",
			want:  checkInfo,
		},
		{
			err:   windows.ERROR_FILE_NOT_FOUND,
			label: "FI config directory",
			want:  checkFail,
		},
		{
			err: errors.New(
				"access denied",
			),
			label: "FI CRL active file",
			want:  checkFail,
		},
	}

	for _, test := range tests {
		got :=
			aclDiscoveryFailureStatus(
				test.label,
				test.err,
			)

		if got != test.want {
			t.Fatalf(
				"label=%q err=%v status=%s want=%s",
				test.label,
				test.err,
				got,
				test.want,
			)
		}
	}
}
