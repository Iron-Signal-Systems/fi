package records

// MetadataObservation records bounded NTFS metadata using canonical string values.
type MetadataObservation struct {
	State          ObservationState `json:"state"`
	ObjectKind     string           `json:"object_kind,omitempty"`
	LogicalSize    string           `json:"logical_size,omitempty"`
	AllocatedSize  string           `json:"allocated_size,omitempty"`
	CreationTime   string           `json:"creation_time,omitempty"`
	LastWriteTime  string           `json:"last_write_time,omitempty"`
	ChangeTime     string           `json:"change_time,omitempty"`
	LastAccessTime string           `json:"last_access_time,omitempty"`
	RawAttributes  string           `json:"raw_attributes,omitempty"`
	LinkCount      string           `json:"link_count,omitempty"`
	ReasonCode     string           `json:"reason_code,omitempty"`
}

// StreamObservation records one enumerated NTFS stream and its source-reported sizes.
// Hashing and classification are separate observations and are intentionally not
// fabricated by this low-level collector.
type StreamObservation struct {
	Identity      StreamIdentity   `json:"identity"`
	State         ObservationState `json:"state"`
	LogicalSize   string           `json:"logical_size,omitempty"`
	AllocatedSize string           `json:"allocated_size,omitempty"`
	ReasonCode    string           `json:"reason_code,omitempty"`
}

// StreamInventory records the completeness of stream enumeration for an object.
type StreamInventory struct {
	State      ObservationState    `json:"state"`
	Streams    []StreamObservation `json:"streams"`
	ReasonCode string              `json:"reason_code,omitempty"`
}
