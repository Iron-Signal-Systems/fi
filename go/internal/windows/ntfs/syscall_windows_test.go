// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package ntfs

import (
	"encoding/binary"
	"errors"
	"testing"
)

// NextEntryOffset must never point into the current variable-length stream name.
func TestParseStreamInfoRejectsOffsetInsideName(t *testing.T) {
	buffer := make([]byte, 64)

	// Header is 24 bytes and the name is 20 bytes, so the next entry cannot
	// begin before align8(44) == 48.
	binary.LittleEndian.PutUint32(buffer[0:4], 24)
	binary.LittleEndian.PutUint32(buffer[4:8], 20)

	_, err := parseStreamInfo(buffer)
	if !errors.Is(err, ErrMalformedStreamInfo) {
		t.Fatalf("error = %v, want ErrMalformedStreamInfo", err)
	}
}
