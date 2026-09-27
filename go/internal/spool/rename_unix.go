// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux || freebsd

package spool

import "os"

// Unix builds use the native rename semantics exposed by os.Rename. Phase 1 production
// spool finalization remains the Windows implementation.
func durableRename(source string, destination string) error {
	return os.Rename(source, destination)
}
