package records

// RecordReference binds another FI record by type and SHA-512 identity.
type RecordReference struct {
	RecordType string `json:"record_type"`
	SHA512     string `json:"sha512"`
}

// ComponentIdentity binds a producing component to an exact release and binary.
type ComponentIdentity struct {
	Product      string `json:"product"`
	Release      string `json:"release"`
	BinarySHA512 string `json:"binary_sha512"`
}

// VolumeIdentity identifies one accepted NTFS volume.
type VolumeIdentity struct {
	MethodVersion string `json:"method_version"`
	VolumeGUID    string `json:"volume_guid"`
	VolumeSerial  string `json:"volume_serial"`
}

// NTFSObjectIdentity identifies one NTFS object independently of path text.
type NTFSObjectIdentity struct {
	MethodVersion       string             `json:"method_version"`
	FileReferenceNumber string             `json:"file_reference_number"`
	SequenceNumber      string             `json:"sequence_number"`
	Confidence          IdentityConfidence `json:"confidence"`
}

// StreamIdentity identifies one observable NTFS stream on a governed object.
// RawNameUTF16LEBase64URL preserves the exact name returned by Windows, including
// stream type (for example ::$DATA or :name:$DATA).
type StreamIdentity struct {
	Kind                    StreamKind `json:"kind"`
	NameUTF16LEBase64URL    string     `json:"name_utf16le_base64url,omitempty"`
	StreamType              string     `json:"stream_type,omitempty"`
	RawNameUTF16LEBase64URL string     `json:"raw_name_utf16le_base64url"`
}

// GovernedRootIdentity binds an FI governed scope to the exact opened NTFS root.
type GovernedRootIdentity struct {
	ScopeID                       string              `json:"scope_id"`
	RequestedPathUTF16LEBase64URL string              `json:"requested_path_utf16le_base64url"`
	ResolvedPathUTF16LEBase64URL  string              `json:"resolved_path_utf16le_base64url,omitempty"`
	State                         ObservationState    `json:"state"`
	MethodVersion                 string              `json:"method_version"`
	VolumeIdentity                *VolumeIdentity     `json:"volume_identity,omitempty"`
	ObjectIdentity                *NTFSObjectIdentity `json:"object_identity,omitempty"`
	ReasonCode                    string              `json:"reason_code,omitempty"`
}

// PathContainment records a handle-derived governed-scope conclusion.
type PathContainment struct {
	State         ObservationState `json:"state"`
	MethodVersion string           `json:"method_version"`
	ReasonCode    string           `json:"reason_code,omitempty"`
}

// PathBinding records one observed path without treating path text as object identity.
type PathBinding struct {
	PathUTF16LEBase64URL string              `json:"path_utf16le_base64url"`
	State                ObservationState    `json:"state"`
	ParentObject         *NTFSObjectIdentity `json:"parent_object,omitempty"`
}

// ObservationWarning is one bounded stable warning emitted while observing source state.
type ObservationWarning struct {
	Code   string `json:"code"`
	Detail string `json:"detail,omitempty"`
}
