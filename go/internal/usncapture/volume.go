// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usncapture

import (
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "strings"

    "github.com/Iron-Signal-Systems/fi/go/internal/records"
)

// VolumeCaptureScopeID gives one durable raw capture owner to all configured
// governed roots on the SAME NTFS volume. It does not include the journal ID:
// journal recreation is detected as a continuity conflict, never masked by a
// different queue path. Source processing fans out to per-root scope IDs.
func VolumeCaptureScopeID(volume records.VolumeIdentity) (string, error) {
    if err := records.ValidateVolumeIdentity(volume); err != nil {
        return "", fmt.Errorf("invalid volume capture identity: %w", err)
    }
    data := "fi-volume-usn-capture/1\x00" +
        volume.MethodVersion + "\x00" +
        strings.ToLower(volume.VolumeGUID) + "\x00" +
        volume.VolumeSerial
    digest := sha256.Sum256([]byte(data))
    return "volume-" + hex.EncodeToString(digest[:16]), nil
}
