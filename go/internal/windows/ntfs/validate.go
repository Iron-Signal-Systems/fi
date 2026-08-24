// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package ntfs

import "github.com/Iron-Signal-Systems/fi/go/internal/records"

// ValidateObservation checks the shared record representation immediately
// before a successful NTFS observation leaves this package.
//
// Windows API/path safety is checked while collecting. This function checks the
// record boundary: required identities, canonical values, parent binding,
// observation time, security state, reparse state/payload, stream ordering,
// optional integrated content hashes, collection entry/method/status, warning
// ordering, and whole-observation state consistency.
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
	if err := records.ValidateParentObjectBinding(observation.ParentBinding); err != nil {
		return err
	}
	if err := records.ValidateSubjectKind(observation.SubjectKind); err != nil {
		return err
	}
	if err := records.ValidatePathBinding(observation.PathBinding); err != nil {
		return err
	}
	if err := records.ValidateObservedAt(observation.ObservedAt); err != nil {
		return err
	}
	if err := records.ValidateMetadataObservation(observation.Metadata); err != nil {
		return err
	}
	if err := records.ValidateSecurityObservation(observation.Security); err != nil {
		return err
	}
	if err := records.ValidateSACLObservation(observation.SACL); err != nil {
		return err
	}
	if err := records.ValidateReparseObservation(observation.Reparse); err != nil {
		return err
	}
	if err := records.ValidateStreamInventory(observation.StreamInventory); err != nil {
		return err
	}
	if observation.ContentHashes != nil {
		if err := records.ValidateContentHashObservation(*observation.ContentHashes); err != nil {
			return err
		}
	}
	switch observation.CollectionEntryMethod {
	case CollectionEntryPath, CollectionEntryNTFSFileID:
	default:
		return &records.ValidationError{Code: "UnsupportedValue", Field: "collection_entry_method"}
	}
	if observation.CollectionMethod != records.CollectionDirectWindowsNTFS {
		return &records.ValidationError{Code: "UnsupportedValue", Field: "collection_method"}
	}
	if err := records.ValidateObservationStatus(observation.ObservationStatus); err != nil {
		return err
	}
	if err := records.ValidateObservationWarnings(observation.Warnings); err != nil {
		return err
	}
	return validateObservationConsistency(observation)
}
