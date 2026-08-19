// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

// Package ntfs collects bounded Windows/NTFS object identity, metadata, path
// containment, and stream inventory from explicitly governed local NTFS roots.
//
// It is intentionally source-side and read-only. Security descriptors, share
// state, directory identity, USN consumption, Windows event collection, EA,
// reparse payloads, object IDs, hashing, and other Phase 1 capabilities are
// separate work still to be implemented around this foundation.
package ntfs
