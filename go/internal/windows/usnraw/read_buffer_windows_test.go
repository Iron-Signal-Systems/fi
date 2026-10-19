// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package usnraw

import "testing"

func TestValidateReadBufferBytes(t *testing.T) {
	for _, size := range []int{1 << 20, 2 << 20, 4 << 20, 8 << 20, 16 << 20, 32 << 20, 64 << 20} {
		if err := validateReadBufferBytes(size); err != nil {
			t.Errorf("size %d rejected: %v", size, err)
		}
	}
	for _, size := range []int{0, 1024, 1<<20 + 1, 65 << 20} {
		if err := validateReadBufferBytes(size); err == nil {
			t.Errorf("size %d unexpectedly accepted", size)
		}
	}
}
