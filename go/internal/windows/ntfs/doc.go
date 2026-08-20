// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

// Package ntfs contains the Windows-specific direct NTFS collector.

// This package opens governed local NTFS objects read-only and collects the
// source facts that only Windows can provide directly: volume/object identity,
// metadata, governed-root containment, and stream/ADS inventory.

// Shared FI record definitions live under internal/records. Staging, transport,
// USN, security-descriptor, share, hashing, and other responsibilities belong in
// their own packages when those capabilities are implemented.

package ntfs
