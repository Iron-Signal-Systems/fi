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
// collected security state, collected reparse state and payload where
// applicable, attempted stream enumeration, and completed consistency checks.
//
// ObservedAt is the source collector's UTC time when the facts represented by
// this observation finished collection. It is distinct from NTFS timestamps.
//
// This is not a Windows API structure and is not the backend database schema.
type Observation struct {
	GovernedRoot      records.GovernedRootIdentity `json:"governed_root"`
	Containment       records.PathContainment      `json:"containment"`
	VolumeIdentity    records.VolumeIdentity       `json:"volume_identity"`
	ObjectIdentity    records.NTFSObjectIdentity   `json:"object_identity"`
	SubjectKind       records.SubjectKind          `json:"subject_kind"`
	PathBinding       records.PathBinding          `json:"path_binding"`
	ObservedAt        string                       `json:"observed_at"`
	Metadata          records.MetadataObservation  `json:"metadata"`
	Security          records.SecurityObservation  `json:"security"`
	SACL              records.SACLObservation      `json:"sacl"`
	Reparse           records.ReparseObservation   `json:"reparse"`
	StreamInventory   records.StreamInventory      `json:"stream_inventory"`
	CollectionMethod  records.CollectionMethod     `json:"collection_method"`
	ObservationStatus records.ObservationStatus    `json:"observation_status"`
	Warnings          []records.ObservationWarning `json:"warnings"`
}
