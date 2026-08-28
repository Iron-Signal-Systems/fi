// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package spool

import "os"

// Linux exists for repository CI and future platform work. Phase 1 production
// spool finalization is currently the Windows implementation.
func durableRename(source string, destination string) error {
	return os.Rename(source, destination)
}
