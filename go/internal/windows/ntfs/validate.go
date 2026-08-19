package ntfs

import "github.com/Iron-Signal-Systems/fi/go/internal/records"

// ValidateObservation validates every source component emitted by the NTFS collector.
func ValidateObservation(observation Observation) error {
	if err := records.ValidateGovernedRootIdentity(observation.GovernedRoot); err != nil {
		return err
	}
	if err := records.ValidatePathContainment(observation.Containment); err != nil {
		return err
	}
	if err := records.ValidateVolumeIdentity(observation.VolumeIdentity); err != nil {
		return err
	}
	if err := records.ValidateNTFSObjectIdentity(observation.ObjectIdentity); err != nil {
		return err
	}
	if err := records.ValidateSubjectKind(observation.SubjectKind); err != nil {
		return err
	}
	if err := records.ValidatePathBinding(observation.PathBinding); err != nil {
		return err
	}
	if err := records.ValidateMetadataObservation(observation.Metadata); err != nil {
		return err
	}
	if err := records.ValidateStreamInventory(observation.StreamInventory); err != nil {
		return err
	}
	if observation.CollectionMethod != records.CollectionDirectWindowsNTFS {
		return &records.ValidationError{Code: "UnsupportedValue", Field: "collection_method"}
	}
	if err := records.ValidateObservationStatus(observation.ObservationStatus); err != nil {
		return err
	}
	return records.ValidateObservationWarnings(observation.Warnings)
}
