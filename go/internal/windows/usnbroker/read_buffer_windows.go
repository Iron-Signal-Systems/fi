// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package usnbroker

import "sync/atomic"

// The collector configures this before starting source workers. The privileged
// helper always validates and enforces its own upper bound independently.
var configuredReadBufferMiB atomic.Uint32

func ConfigureReadBufferMiB(size uint32) error {
	if err := validateReadBufferMiB(size); err != nil {
		return err
	}
	configuredReadBufferMiB.Store(size)
	return nil
}

func currentReadBufferMiB() uint32 {
	size := configuredReadBufferMiB.Load()
	if size == 0 {
		return DefaultUSNReadBufferMiB
	}
	return size
}
