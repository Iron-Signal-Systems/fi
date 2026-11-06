//go:build freebsd

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// SIGKILL can only be selected via the W128/K32 isolated private CLI gate.
package recordingest

import (
	"os"
	"syscall"
)

func terminateDeferredExperimentForTest() error {
	return syscall.Kill(os.Getpid(), syscall.SIGKILL)
}
