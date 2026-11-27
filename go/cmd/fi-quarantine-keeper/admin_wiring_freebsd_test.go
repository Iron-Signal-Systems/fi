// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package main

import (
	"os"
	"strings"
	"testing"
)

func TestKeeperAdminOptInRequired(t *testing.T) {
	source, err := os.ReadFile("main_freebsd.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, must := range []string{
		`flags.Bool("admin-enable", false`,
		`store.VerifyReleaseHistory(*historyRoot)`,
		`quarantinekeeper.BindAdminSocket(adminPolicy)`,
		`quarantinekeeper.ProtectedAdminReleaseHandler(store`,
		`quarantinekeeper.ServeAdminReleaseConnections(ctx, adminListener`,
		`if !*adminEnabled`,
	} {
		if !strings.Contains(text, must) {
			t.Fatalf("missing administrative authority contract: %s", must)
		}
	}
}
