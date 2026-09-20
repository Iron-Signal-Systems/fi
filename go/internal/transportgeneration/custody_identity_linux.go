// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package transportgeneration

// DurableCustodyObjectName returns the deterministic filename for one
// generation's immutable FIGT custody object.
func DurableCustodyObjectName(
	sourceID string,
	generationID string,
) string {
	return generationCustodyObjectName(
		sourceID,
		generationID,
	)
}
