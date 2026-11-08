// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package volumediscovery

import (
	"context"
	"syscall"
	"testing"
)

func TestNativeMountPathListDecoder(t *testing.T) {
	tests := []struct {
		name  string
		input []uint16
		want  int
		bad   bool
	}{
		{"lettered", syscall.StringToUTF16(`C:\` + "\x00"), 1, false},
		{"unmounted", []uint16{0}, 0, false},
		{"unterminated", []uint16{'C', ':', '\\'}, 0, true},
		{"empty buffer", nil, 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeMountPathList(tc.input)
			if (err != nil) != tc.bad {
				t.Fatalf("decodeMountPathList error=%v, wantBad=%v", err, tc.bad)
			}
			if err == nil && len(got) != tc.want {
				t.Fatalf("decodeMountPathList returned %v, wanted count %d", got, tc.want)
			}
		})
	}
}

func TestNativeEnumerationRespectsCancellation(t *testing.T) {
	if _, err := Enumerate(nil); err == nil {
		t.Fatal("nil context must be rejected before any native calls")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Enumerate(ctx); err != context.Canceled {
		t.Fatalf("canceled discovery returned %v", err)
	}
}

// This test runs against GitHub's actual Windows runner. It never enrolls a
// volume, changes audit settings, opens a raw device or queries a USN journal.
// It tests native enumeration + filesystem and FILE_ID_INFO attestation only.
// It does not replace adminbox validation on the supported Server builds.
func TestNativeReadOnlyVolumeDiscovery(t *testing.T) {
	items, err := Enumerate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(items) == 0 {
		t.Fatal("Windows enumerator returned no volumes")
	}
	foundEligible := false
	for _, item := range items {
		canonical, err := canonicalGUID(item.GUID)
		if err != nil || item.GUID != canonical {
			t.Fatalf("native volume has noncanonical GUID %q, error=%v", item.GUID, err)
		}
		if item.Status == Eligible {
			foundEligible = true
			if item.FileSystem != "NTFS" || validSerial(item.Serial64) != nil {
				t.Fatalf("eligible native volume lacks full-width identity: %+v", item)
			}
		}
		if item.Status != Eligible && item.Status != Unsupported && item.Status != Unavailable {
			t.Fatalf("native discovery returned unknown status: %+v", item)
		}
	}
	if !foundEligible {
		t.Fatal("Windows runner did not expose an attestable NTFS volume")
	}
}
