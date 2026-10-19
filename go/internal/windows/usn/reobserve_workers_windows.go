// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package usn

import (
	"fmt"
	"sync/atomic"
)

const MaxReobserveWorkers = 16

var configuredReobserveWorkers atomic.Int32

// ConfigureReobserveWorkers is called from validated collector configuration
// before starting root catch-up. The configuration is per collector process.
func ConfigureReobserveWorkers(workers int) error {
	if workers < 1 || workers > MaxReobserveWorkers {
		return fmt.Errorf("USN re-observation workers must be between 1 and %d", MaxReobserveWorkers)
	}
	configuredReobserveWorkers.Store(int32(workers))
	return nil
}

func currentReobserveWorkers() int {
	workers := configuredReobserveWorkers.Load()
	if workers == 0 {
		return reobserveWorkerCount // Existing candidate default: eight.
	}
	return int(workers)
}
