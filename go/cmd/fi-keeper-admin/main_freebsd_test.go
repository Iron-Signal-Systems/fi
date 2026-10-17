// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package main

import "testing"

func TestAdminCLIRejectsUnauthorizedOrIncompleteRelease(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"release"},
		{"read"},
		{"release", "-source", "a.example", "-confirm", "b.example", "-reference", "X", "-justification", "reviewed"},
	} {
		if err := run(args); err == nil {
			t.Fatalf("invalid administrative command accepted: %v", args)
		}
	}
}
