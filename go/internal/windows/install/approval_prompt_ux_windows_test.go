// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"bytes"
	"strings"
	"testing"
)

func TestWriteFailClosedApprovalPrompt(
	t *testing.T,
) {
	t.Parallel()

	tests :=
		[]struct {
			approval string
			token    string
		}{
			{
				approval: "configuration approval",
				token:    "APPROVE-CONFIG 0123456789ABCDEF",
			},
			{
				approval: "Approval 1",
				token:    "APPROVE-1 0123456789ABCDEF",
			},
			{
				approval: "Approval 2",
				token:    "APPROVE-2 0123456789ABCDEF",
			},
			{
				approval: "CA template-publication approval",
				token:    "APPROVE-CA-PUBLISH 0123456789ABCDEF",
			},
		}

	for _, test := range tests {
		test := test

		t.Run(
			test.approval,
			func(t *testing.T) {
				t.Parallel()

				var output bytes.Buffer

				writeFailClosedApprovalPrompt(
					&output,
					test.token,
					test.approval,
				)

				got :=
					output.String()

				required :=
					[]string{
						"Type exactly: " +
							test.token,
						"Any other input is treated as rejection.",
						"The installer will exit with a non-zero status and " +
							test.approval +
							" will not be applied.",
						"> ",
					}

				for _, value := range required {
					if !strings.Contains(
						got,
						value,
					) {
						t.Fatalf(
							"prompt missing %q:\n%s",
							value,
							got,
						)
					}
				}
			},
		)
	}
}
