//go:build freebsd

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
	"errors"
	"syscall"
)

// FreeBSD ru_maxrss is a process high-water RSS measurement in KiB.
// It is not the current RSS, so a pressure-triggered chunk reduction is
// conservative until the W256 window commits or aborts.
func privateW256PeakRSSBytes() (uint64, error) {
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		return 0, err
	}
	if usage.Maxrss <= 0 {
		return 0, errors.New("zero process RSS high-water")
	}
	return uint64(usage.Maxrss) * 1024, nil
}
