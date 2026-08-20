// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package ntfs

import "testing"

func FuzzParseStreamInfo(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, fileStreamInfoHeader))
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = func() error {
			_, err := parseStreamInfo(data)
			return err
		}()
	})
}

func FuzzParseReparseData(f *testing.F) {
	f.Add([]byte{})
	f.Add(testMountPointReparseData(`\??\C:\target`, `C:\target`))
	f.Add(testSymbolicLinkReparseData(`\??\C:\target`, `C:\target`, 0))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseReparseData(data)
	})
}
