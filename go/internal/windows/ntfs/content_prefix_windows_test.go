// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package ntfs

import (
	"bytes"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func TestContentPrefixWriterRetainsOnlyFirstBytes(t *testing.T) {
	writer := &contentPrefixWriter{value: make([]byte, 0, records.ContentPrefixMaxBytes)}
	first := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	second := []byte{10, 11, 12, 13, 14, 15, 16, 17, 18, 19}

	if written, err := writer.Write(first); err != nil || written != len(first) {
		t.Fatalf("Write(first) = (%d, %v), want (%d, nil)", written, err, len(first))
	}
	if written, err := writer.Write(second); err != nil || written != len(second) {
		t.Fatalf("Write(second) = (%d, %v), want (%d, nil)", written, err, len(second))
	}

	want := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	if !bytes.Equal(writer.value, want) {
		t.Fatalf("prefix = %v, want %v", writer.value, want)
	}
}

func TestContentPrefixWriterAcceptsEmptyWrite(t *testing.T) {
	writer := &contentPrefixWriter{value: make([]byte, 0, records.ContentPrefixMaxBytes)}
	if written, err := writer.Write(nil); err != nil || written != 0 {
		t.Fatalf("Write(nil) = (%d, %v), want (0, nil)", written, err)
	}
	if len(writer.value) != 0 {
		t.Fatalf("prefix length = %d, want 0", len(writer.value))
	}
}
