// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package records

// Used by Windows Systems and Backend Recorder.
//
// Windows creates these identities from NTFS facts. Backend components consume
// the same values when storing, correlating, and reconstructing source history.

// VolumeIdentity identifies the NTFS volume containing a governed root or
// collected object.
//
// Windows creates this from information obtained through an open object handle.
// FI keeps the volume identity with the NTFS object identity so a drive letter
// or pathname is never treated as the object's identity.
type VolumeIdentity struct {
	MethodVersion string `json:"method_version"`
	VolumeGUID    string `json:"volume_guid"`
	VolumeSerial  string `json:"volume_serial"`
}

// NTFSObjectIdentity identifies a specific NTFS object independently of its
// current pathname.
//
// Windows creates this from FILE_ID_INFO returned for an open object handle.
// FileReferenceNumber identifies the NTFS file record and SequenceNumber helps
// distinguish later reuse of that file record after an older object is deleted.
type NTFSObjectIdentity struct {
	MethodVersion       string `json:"method_version"`
	FileReferenceNumber string `json:"file_reference_number"`
	SequenceNumber      string `json:"sequence_number"`
}

// StreamIdentity identifies one NTFS stream belonging to an NTFS object.
//
// Windows creates this while enumerating FILE_STREAM_INFO. DefaultData is the
// normal ::$DATA stream. NamedData is an alternate data stream such as
// :Zone.Identifier:$DATA.
//
// RawNameUTF16LEBase64URL preserves the exact UTF-16 name returned by Windows.
type StreamIdentity struct {
	Kind                    StreamKind `json:"kind"`
	NameUTF16LEBase64URL    string     `json:"name_utf16le_base64url,omitempty"`
	StreamType              string     `json:"stream_type,omitempty"`
	RawNameUTF16LEBase64URL string     `json:"raw_name_utf16le_base64url"`
}

// GovernedRootIdentity records the exact NTFS object FI accepted as the root of
// one collection scope.
//
// Windows creates this by opening the configured governed-root path and
// resolving the actual volume and object identity. Collection fails instead of
// creating this value if the root cannot be established safely.
type GovernedRootIdentity struct {
	ScopeID                       string             `json:"scope_id"`
	RequestedPathUTF16LEBase64URL string             `json:"requested_path_utf16le_base64url"`
	ResolvedPathUTF16LEBase64URL  string             `json:"resolved_path_utf16le_base64url"`
	MethodVersion                 string             `json:"method_version"`
	VolumeIdentity                VolumeIdentity     `json:"volume_identity"`
	ObjectIdentity                NTFSObjectIdentity `json:"object_identity"`
}

// PathContainment records how FI proved that the opened target was inside the
// opened governed root.
//
// Presence of this value means containment succeeded. Failed containment is a
// collection error and does not create a successful observation.
type PathContainment struct {
	MethodVersion string `json:"method_version"`
}

// PathBinding records the pathname observed for an NTFS object at collection
// time.
//
// FI treats the path as a name/location associated with the object, not as the
// object identity. NTFSObjectIdentity remains the object identity if a path is
// renamed, moved, hard-linked, or later reused by another object.
type PathBinding struct {
	PathUTF16LEBase64URL string `json:"path_utf16le_base64url"`
}

// END Used by Windows Systems and Backend Recorder.
