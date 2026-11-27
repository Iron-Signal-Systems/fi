// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyAuthenticodeRejectsUnsignedFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(
		t.TempDir(),
		"unsigned.exe",
	)
	if err := os.WriteFile(
		path,
		[]byte("not an Authenticode-signed PE image"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	state := verifyAuthenticode(path)
	if state.Trusted {
		t.Fatal(
			"unsigned file unexpectedly passed Authenticode verification",
		)
	}
	if state.Error == "" {
		t.Fatal(
			"unsigned file rejection did not preserve the native trust error",
		)
	}
}
