// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// NewAttemptID returns an unpredictable identity for one explicit ingest attempt.
func NewAttemptID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate FI ingest attempt identity: %w", err)
	}
	return "fi-ingest-attempt-" + hex.EncodeToString(raw[:]), nil
}
