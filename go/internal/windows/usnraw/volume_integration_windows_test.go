// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package usnraw

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/windows/volumediscovery"
)

// TestNativeEnrolledVolumeUSNReadOnly is an explicitly opt-in characterization
// of the Windows raw-volume handle/identity/USN contract on adminbox. It makes
// no filesystem/journal/service/PKI/security-policy mutations. It never runs
// during ordinary go test ./... unless the exact approval token is present.
//
// This confirms local native access only. Full broker service-SID/gMSA,
// authenticated pipe, custody and installer acceptance remain separate gates.
func TestNativeEnrolledVolumeUSNReadOnly(t *testing.T) {
	if os.Getenv("FI_TEST_NATIVE_USN_APPROVAL") != "APPROVE-READ-ONLY-FI-USN" {
		t.Skip("native FI USN volume test requires explicit approval")
	}
	guid := os.Getenv("FI_TEST_NATIVE_USN_GUID")
	serial := os.Getenv("FI_TEST_NATIVE_USN_SERIAL64")
	if _, _, err := enrolledVolumeDevicePath(guid, serial); err != nil {
		t.Fatalf("invalid approved native FI USN fixture: %v", err)
	}
	native, err := volumediscovery.Enumerate(context.Background())
	if err != nil {
		t.Fatalf("native volume inventory failed: %v", err)
	}
	found := false
	for _, item := range native {
		if !strings.EqualFold(item.GUID, guid) {
			continue
		}
		found = true
		if item.Status != volumediscovery.Eligible || item.Serial64 != serial {
			t.Fatalf("enrollment differs from freshly discovered native FILE_ID_INFO: %+v", item)
		}
	}
	if !found {
		t.Fatal("enrolled volume GUID not found in native inventory")
	}
	journal, err := QueryEnrolledVolume(guid, serial)
	if err != nil {
		t.Fatalf("same-handle 64-bit serial and USN query failed: %v", err)
	}
	if journal.NextUSN < 0 || journal.FirstUSN < 0 || journal.JournalID == 0 {
		t.Fatalf("native journal returned invalid state: %+v", journal)
	}
	journalAtRead, raw, err := ReadEnrolledVolume(guid, serial, journal.NextUSN)
	if err != nil {
		t.Fatalf("same-handle volume USN read failed: %v", err)
	}
	if len(raw) < 8 || len(raw) > readBufferSize {
		t.Fatalf("unexpected bounded native USN read size %d", len(raw))
	}
	if journalAtRead.JournalID != journal.JournalID {
		t.Fatalf("journal changed across explicitly observed read: query=%d read=%d",
			journal.JournalID, journalAtRead.JournalID)
	}
	t.Logf("FI NATIVE USN READ-ONLY PASS volume=%s serial64=%s journal_id=%d read_bytes=%d",
		guid, serial, journal.JournalID, len(raw))
}
