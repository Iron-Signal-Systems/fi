// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportgeneration

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// NewGenerationID returns a source-local identifier suitable for durable
// generation directory ordering and identity binding.
func NewGenerationID() (string, error) {
	var random [8]byte

	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}

	return time.Now().UTC().Format("20060102T150405.000000000Z") +
		"-" +
		hex.EncodeToString(random[:]), nil
}
