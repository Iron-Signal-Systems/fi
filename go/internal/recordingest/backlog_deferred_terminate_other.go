//go:build !freebsd

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import "errors"

// Never kill a Windows/Linux CI process while exercising portable tests.
func terminateDeferredExperimentForTest() error {
	return errors.New("FI SIGKILL deferred fault requires isolated FreeBSD trial")
}
