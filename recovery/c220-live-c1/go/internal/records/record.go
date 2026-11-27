// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package records

// Used by Windows Systems and Backend Recorder.
//
// These types describe FI records and the component that produced them. They
// are record/staging infrastructure and are not Windows filesystem identities.

// RecordReference identifies another FI record by record type and SHA-512.
//
// Windows uses this during source-record creation or staging when one record
// needs to refer to another FI record without embedding or duplicating it.
//
// This does NOT identify the Windows file being collected. NTFSObjectIdentity
// identifies the Windows NTFS object.
type RecordReference struct {
	RecordType string `json:"record_type"`
	SHA512     string `json:"sha512"`
}

// ComponentIdentity records exactly which FI executable produced a source
// record.
//
// Windows source-record creation/staging can populate this with the FI product,
// release, and SHA-512 of the exact executable binary. Backend components can
// then determine which exact FI binary produced the record.
//
// This does NOT identify the Windows file being observed.
type ComponentIdentity struct {
	Product      string `json:"product"`
	Release      string `json:"release"`
	BinarySHA512 string `json:"binary_sha512"`
}

// END Used by Windows Systems and Backend Recorder.
