// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usncapture

import (
    "strings"
    "testing"

    "github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func TestOneRawCaptureOwnerPerVolume(t *testing.T) {
    volume := exampleAnchor().VolumeIdentity
    volume.VolumeGUID = strings.Replace(volume.VolumeGUID, "11111111-2222", "abcdeabc-2222", 1)
    a, err := VolumeCaptureScopeID(volume)
    if err != nil || !strings.HasPrefix(a, "volume-") || len(a) != len("volume-")+32 {
        t.Fatalf("invalid volume capture scope: %q %v", a, err)
    }
    upper := volume
    upper.VolumeGUID = strings.Replace(upper.VolumeGUID, "abcdeabc-2222", "ABCDEABC-2222", 1)
    b, err := VolumeCaptureScopeID(upper)
    if err != nil || a != b {
        t.Fatalf("case difference duplicated a volume queue: %q %q %v", a, b, err)
    }
    different := volume
    different.VolumeSerial = "10"
    c, err := VolumeCaptureScopeID(different)
    if err != nil || a == c {
        t.Fatalf("different volume reused capture queue: %q %q %v", a, c, err)
    }
}
func TestVolumeCaptureScopeRejectsUnknownVolume(t *testing.T) {
    if _, err := VolumeCaptureScopeID(records.VolumeIdentity{}); err == nil {
        t.Fatal("invalid volume was assigned raw capture ownership")
    }
}
