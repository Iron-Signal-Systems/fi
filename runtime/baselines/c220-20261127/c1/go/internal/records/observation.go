// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package records

// Used by Windows Systems and Backend Recorder.
//
// Windows creates these observations from source facts. Backend components
// receive the same values rather than reinterpreting Windows API structures.

// MetadataObservation records the NTFS metadata FI successfully collected for
// one object.
//
// Values are canonical strings because this structure is a shared source-record
// representation that is staged and shipped across system boundaries.
type MetadataObservation struct {
	LogicalSize    string `json:"logical_size"`
	AllocatedSize  string `json:"allocated_size"`
	CreationTime   string `json:"creation_time"`
	LastWriteTime  string `json:"last_write_time"`
	ChangeTime     string `json:"change_time"`
	LastAccessTime string `json:"last_access_time"`
	RawAttributes  string `json:"raw_attributes"`
	LinkCount      string `json:"link_count"`
}

// ObservationWarning records a non-fatal problem found during collection.
//
// Windows emits a warning when FI can still return useful source facts but
// could not prove every expected condition, for example when metadata changed
// during collection or path consistency could not be rechecked.
//
// Fatal failures are returned as errors instead.
type ObservationWarning struct {
	Code   string `json:"code"`
	Detail string `json:"detail,omitempty"`
}

// ReparseObservation records the exact reparse-point state Windows reported for
// one object and the exact reparse buffer when it could be obtained.
//
// State is NotPresent when Windows did not report FILE_ATTRIBUTE_REPARSE_POINT.
// DataState and DataFormat are then NotApplicable.
//
// State is Present when Windows reported FILE_ATTRIBUTE_REPARSE_POINT. Tag
// preserves the exact 32-bit tag. TagName is the exact shared FI mapping or
// NotKnown. RawBufferBase64URL preserves every byte returned by
// FSCTL_GET_REPARSE_POINT.
//
// FI parses only documented structures it understands exactly. MountPoint and
// SymbolicLink expose the documented substitute and print names. A zero-length
// parsed name is represented by an omitted/empty encoded value and is still
// interpreted as the exact zero-length field for that parsed format. Raw means
// FI preserved the buffer without claiming to understand its payload.
type ReparseObservation struct {
	DataFormat                     ReparseDataFormat `json:"data_format"`
	DataState                      ReparseDataState  `json:"data_state"`
	PrintNameUTF16LEBase64URL      string            `json:"print_name_utf16le_base64url,omitempty"`
	RawBufferBase64URL             string            `json:"raw_buffer_base64url,omitempty"`
	ReasonCode                     string            `json:"reason_code,omitempty"`
	State                          ReparseState      `json:"state"`
	SubstituteNameUTF16LEBase64URL string            `json:"substitute_name_utf16le_base64url,omitempty"`
	SymbolicLinkFlags              string            `json:"symbolic_link_flags,omitempty"`
	Tag                            string            `json:"tag,omitempty"`
	TagName                        string            `json:"tag_name,omitempty"`
}

// StreamInventory records the result of enumerating all streams for one object.
//
// Stream enumeration is allowed to fail without discarding otherwise useful
// object identity and metadata. State is Present when enumeration succeeded and
// Error when it failed. Error requires ReasonCode and an empty Streams list.
type StreamInventory struct {
	State      ObservationState    `json:"state"`
	Streams    []StreamObservation `json:"streams"`
	ReasonCode string              `json:"reason_code,omitempty"`
}

// StreamObservation records one stream returned by Windows and the sizes
// Windows reported for that stream.
//
// Hashing and classification are separate capabilities and are not represented
// here unless those capabilities actually collect them.
type StreamObservation struct {
	Identity      StreamIdentity `json:"identity"`
	LogicalSize   string         `json:"logical_size"`
	AllocatedSize string         `json:"allocated_size"`
}

// END Used by Windows Systems and Backend Recorder.
