//go:build !freebsd

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import "errors"

// A W256 private memory-gated run must not silently fall back to a
// Go-only memory estimator on unsupported operating systems.
func privateW256PeakRSSBytes() (uint64, error) {
	return 0, errors.New("W256 RSS governor requires FreeBSD")
}
