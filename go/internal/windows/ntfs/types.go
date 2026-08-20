// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package ntfs

import "github.com/Iron-Signal-Systems/fi/go/internal/records"

const (
	// ContainmentMethodVersion identifies the current handle-resolved
	// volume-GUID containment check.
	ContainmentMethodVersion = "windows-final-volume-path-containment/0.1"

	// IdentityMethodVersion identifies the current Windows FILE_ID_INFO to NTFS
	// object-identity conversion.
	IdentityMethodVersion = "windows-file-id-info-ntfs/0.1"
)

// Observation is the result of one direct Windows NTFS collection.
//
// The NTFS collector creates this structure after it has established the
// governed root, proved containment, collected object identity/metadata,
// collected reparse state, and attempted stream enumeration. Windows
// record/staging code can consume this result next.
//
// This is not a Windows API structure and is not the backend database schema.
type Observation struct {
	GovernedRoot      records.GovernedRootIdentity `json:"governed_root"`
	Containment       records.PathContainment      `json:"containment"`
	VolumeIdentity    records.VolumeIdentity       `json:"volume_identity"`
	ObjectIdentity    records.NTFSObjectIdentity   `json:"object_identity"`
	SubjectKind       records.SubjectKind          `json:"subject_kind"`
	PathBinding       records.PathBinding          `json:"path_binding"`
	Metadata          records.MetadataObservation  `json:"metadata"`
	Reparse           records.ReparseObservation   `json:"reparse"`
	StreamInventory   records.StreamInventory      `json:"stream_inventory"`
	CollectionMethod  records.CollectionMethod     `json:"collection_method"`
	ObservationStatus records.ObservationStatus    `json:"observation_status"`
	Warnings          []records.ObservationWarning `json:"warnings"`
}
