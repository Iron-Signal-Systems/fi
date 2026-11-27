// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package main

import (
	"os"
	"testing"
)

func m1PrivateQuarantineTestDir(t *testing.T) string {
	t.Helper()

	root := t.TempDir()

	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}

	return root
}
