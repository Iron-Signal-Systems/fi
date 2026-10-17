// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package ldapsecure

import (
	"strings"
	"testing"
)

func TestOpenRejectsEmptyHost(
	t *testing.T,
) {
	if _, err := Open(
		"   ",
	); err == nil {
		t.Fatal(
			"empty LDAP host was unexpectedly accepted",
		)
	}
}

func TestCloseZeroHandle(
	t *testing.T,
) {
	if err := Close(
		0,
	); err != nil {
		t.Fatal(err)
	}
}

func TestReadBaseBinaryRejectsInvalidArguments(
	t *testing.T,
) {
	tests := []struct {
		name      string
		handle    uintptr
		baseDN    string
		filter    string
		attribute string
		maxBytes  int
		want      string
	}{
		{
			name:      "empty base",
			handle:    1,
			baseDN:    "",
			filter:    "(objectClass=cRLDistributionPoint)",
			attribute: "certificateRevocationList",
			maxBytes:  1024,
			want:      "base distinguished name",
		},
		{
			name:      "empty filter",
			handle:    1,
			baseDN:    "CN=Test",
			filter:    "",
			attribute: "certificateRevocationList",
			maxBytes:  1024,
			want:      "filter is required",
		},
		{
			name:      "empty attribute",
			handle:    1,
			baseDN:    "CN=Test",
			filter:    "(objectClass=cRLDistributionPoint)",
			attribute: "",
			maxBytes:  1024,
			want:      "binary attribute is required",
		},
		{
			name:      "invalid maximum",
			handle:    1,
			baseDN:    "CN=Test",
			filter:    "(objectClass=cRLDistributionPoint)",
			attribute: "certificateRevocationList",
			maxBytes:  0,
			want:      "maximum size must be positive",
		},
		{
			name:      "missing session",
			handle:    0,
			baseDN:    "CN=Test",
			filter:    "(objectClass=cRLDistributionPoint)",
			attribute: "certificateRevocationList",
			maxBytes:  1024,
			want:      "session is unavailable",
		},
	}

	for _, test := range tests {
		t.Run(
			test.name,
			func(t *testing.T) {
				_, err := ReadBaseBinary(
					test.handle,
					test.baseDN,
					test.filter,
					test.attribute,
					test.maxBytes,
				)

				if err == nil {
					t.Fatal(
						"invalid LDAP input was unexpectedly accepted",
					)
				}

				if !strings.Contains(
					err.Error(),
					test.want,
				) {
					t.Fatalf(
						"error=%q want substring %q",
						err,
						test.want,
					)
				}
			},
		)
	}
}
