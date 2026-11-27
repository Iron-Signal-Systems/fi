// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build !windows

package spool

import "path/filepath"

func resolveDirectoryPath(
	path string,
) (string, error) {
	return filepath.EvalSymlinks(path)
}

// resolveDirectoryIdentityPath uses the normal platform path resolver on
// non-Windows systems.
func resolveDirectoryIdentityPath(
	path string,
) (
	string,
	error,
) {
	return resolveDirectoryPath(
		path,
	)
}
