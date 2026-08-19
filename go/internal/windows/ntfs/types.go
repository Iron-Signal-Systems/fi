package ntfs

import "github.com/Iron-Signal-Systems/fi/go/internal/records"

const (
	IdentityMethodVersion    = "windows-file-id-info-ntfs/0.1"
	ContainmentMethodVersion = "windows-final-volume-path-containment/0.1"
	CollectionMethodVersion  = "direct-windows-ntfs/0.1"
)

// Observation contains the low-level source facts collected for one governed path.
// It is an implementation result, not the final FI System of Record schema.
type Observation struct {
	GovernedRoot      records.GovernedRootIdentity
	Containment       records.PathContainment
	VolumeIdentity    records.VolumeIdentity
	ObjectIdentity    records.NTFSObjectIdentity
	SubjectKind       records.SubjectKind
	PathBinding       records.PathBinding
	Metadata          records.MetadataObservation
	StreamInventory   records.StreamInventory
	CollectionMethod  records.CollectionMethod
	ObservationStatus records.ObservationStatus
	Warnings          []records.ObservationWarning
}
