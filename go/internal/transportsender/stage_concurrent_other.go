// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux || darwin

package transportsender

import "github.com/Iron-Signal-Systems/fi/go/internal/transportbatch"

func validateConcurrentlyPublishedOutboundFrame(
	path string,
	expected transportbatch.Descriptor,
) (SentFrame, error) {
	return validateStagedOutboundFrame(path, expected)
}
