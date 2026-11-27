// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build !windows

package spool

import (
	"io"
	"sync"
)

var publishBoundaryProcessMutex sync.Mutex

type processPublishBoundaryGuard struct {
	closed bool
}

// AcquirePublishBoundary provides process-local publication serialization on
// non-Windows builds. FI collection/rollover is currently a Windows source
// function; this implementation preserves portable tests and buildability.
func AcquirePublishBoundary() (io.Closer, error) {
	publishBoundaryProcessMutex.Lock()
	return &processPublishBoundaryGuard{}, nil
}

func (guard *processPublishBoundaryGuard) Close() error {
	if guard == nil || guard.closed {
		return nil
	}
	guard.closed = true
	publishBoundaryProcessMutex.Unlock()
	return nil
}
