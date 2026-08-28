// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build darwin

package spool

import "os"

// Darwin is kept explicitly separate from Windows and Linux platform behavior.
func durableRename(source string, destination string) error {
	return os.Rename(source, destination)
}
