// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package usnbroker

import (
	"context"
	"strings"
	"testing"
)

// These invalid-mode cases must fail before looking up service SIDs, creating
// a pipe or performing any Windows operation. The legacy and volume grant
// sets can never be active concurrently on one helper.
func TestUSNBrokerRejectsMissingAndCombinedAuthorityModes(t *testing.T) {
	var legacy authoritySnapshot
	var volumes volumeAuthoritySnapshot

	for _, tc := range []struct {
		name string
		root *authoritySnapshot
		vol *volumeAuthoritySnapshot
	}{
		{"neither", nil, nil},
		{"both", &legacy, &volumes},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := serveWithAuthority(context.Background(), tc.root, tc.vol)
			if err == nil || !strings.Contains(err.Error(), "exactly one authority mode") {
				t.Fatalf("unsafe combined/missing FIUSNReader authority accepted: %v", err)
			}
		})
	}
}
