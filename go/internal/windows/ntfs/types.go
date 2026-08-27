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

// CollectionEntryMethod identifies how FI obtained the initial target handle.
// It does not change the NTFS facts collected after the handle is established.
type CollectionEntryMethod string

const (
	CollectionEntryPath       CollectionEntryMethod = "Path"
	CollectionEntryNTFSFileID CollectionEntryMethod = "NTFSFileID"
)

// Observation is the result of one direct Windows NTFS collection.
//
// The NTFS collector creates this structure after it has established the
// governed root, proved containment, collected object identity/metadata,
// collected the observed path's parent-object binding, collected security state,
// collected reparse state and payload where applicable, attempted stream
// enumeration, and completed consistency checks.
//
// ContentHashes is collected before the public collection call returns. For a
// regular file FI reopens the same exact NTFS object identity with GENERIC_READ
// while the original observation handle is still open, reads the unnamed/default
// $DATA stream once, and calculates MD5, SHA-1, and SHA-256 in that one read.
// Directories report NotApplicable. A content-hash source failure carries its
// own explicit Error state and also makes the enclosing object observation
// Partial with ContentHashFailed; FI does not report a hash-failed file
// observation as fully Complete. Context cancellation is operation control flow
// and is returned as an error rather than converted into a content-source error.
//
// CollectionEntryMethod records whether the initial target handle came from a
// caller path or from OpenFileById. Both entry methods feed the same opened-
// handle collector and therefore produce the same NTFS fact model.
//
// For NTFSFileID collection, PathBinding records the current handle-resolved
// namespace binding discovered after the ID open. It is not the object's
// identity and is not treated as historical authority by itself.
//
// ObservedAt is the source collector's UTC time when the facts represented by
// this observation finished collection. It is distinct from NTFS timestamps.
//
// This is not a Windows API structure and is not the backend database schema.
type Observation struct {
	GovernedRoot          records.GovernedRootIdentity    `json:"governed_root"`
	Containment           records.PathContainment         `json:"containment"`
	VolumeIdentity        records.VolumeIdentity          `json:"volume_identity"`
	ObjectIdentity        records.NTFSObjectIdentity      `json:"object_identity"`
	ParentBinding         records.ParentObjectBinding     `json:"parent_binding"`
	SubjectKind           records.SubjectKind             `json:"subject_kind"`
	PathBinding           records.PathBinding             `json:"path_binding"`
	ObservedAt            string                          `json:"observed_at"`
	Metadata              records.MetadataObservation     `json:"metadata"`
	Security              records.SecurityObservation     `json:"security"`
	SACL                  records.SACLObservation         `json:"sacl"`
	Reparse               records.ReparseObservation      `json:"reparse"`
	StreamInventory       records.StreamInventory         `json:"stream_inventory"`
	ContentHashes         *records.ContentHashObservation `json:"content_hashes,omitempty"`
	CollectionEntryMethod CollectionEntryMethod           `json:"collection_entry_method"`
	CollectionMethod      records.CollectionMethod        `json:"collection_method"`
	ObservationStatus     records.ObservationStatus       `json:"observation_status"`
	Warnings              []records.ObservationWarning    `json:"warnings"`
}
