// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package ntfs

import (
	"strconv"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

const parentBindingUnavailableReason = "ParentBindingUnavailable"

func validateObservationConsistency(observation Observation) error {
	warnings := make(map[string]struct{}, len(observation.Warnings))
	for _, warning := range observation.Warnings {
		warnings[warning.Code] = struct{}{}
	}
	has := func(code string) bool {
		_, ok := warnings[code]
		return ok
	}
	conflict := func(field string) error {
		return &records.ValidationError{Code: "Conflict", Field: field}
	}

	parentError := observation.ParentBinding.State == records.ParentBindingError
	if parentError {
		if observation.ParentBinding.ReasonCode != parentBindingUnavailableReason || !has(parentBindingUnavailableReason) {
			return conflict("parent_binding")
		}
	} else if has(parentBindingUnavailableReason) {
		return conflict("parent_binding")
	}

	streamError := observation.StreamInventory.State == records.ObservationStateError
	if streamError != has("StreamEnumerationFailed") {
		return conflict("stream_inventory")
	}

	securityReadError := observation.Security.State == records.ObservationStateError
	if securityReadError {
		if observation.Security.ReasonCode != "SecurityDescriptorReadFailed" || !has("SecurityDescriptorReadFailed") {
			return conflict("security")
		}
	} else if has("SecurityDescriptorReadFailed") {
		return conflict("security")
	}

	securityParseFailure := observation.Security.State == records.ObservationStatePresent &&
		observation.Security.DataFormat == records.SecurityDataFormatRaw
	if securityParseFailure {
		if observation.Security.ReasonCode != "SecurityDescriptorParseFailed" || !has("SecurityDescriptorParseFailed") {
			return conflict("security")
		}
	} else if has("SecurityDescriptorParseFailed") {
		return conflict("security")
	}

	saclReadError := observation.SACL.State == records.ObservationStateError
	saclPrivilegeWarning := has("SACLPrivilegeUnavailable")
	saclReadWarning := has("SACLDescriptorReadFailed")
	if saclPrivilegeWarning && saclReadWarning {
		return conflict("sacl")
	}
	if saclReadError {
		switch observation.SACL.ReasonCode {
		case "SACLPrivilegeUnavailable":
			if !saclPrivilegeWarning {
				return conflict("sacl")
			}
		case "SACLDescriptorReadFailed":
			if !saclReadWarning {
				return conflict("sacl")
			}
		default:
			return conflict("sacl")
		}
	} else if saclPrivilegeWarning || saclReadWarning {
		return conflict("sacl")
	}

	saclParseFailure := observation.SACL.State == records.ObservationStatePresent &&
		observation.SACL.DataFormat == records.SecurityDataFormatRaw
	if saclParseFailure {
		if observation.SACL.ReasonCode != "SACLDescriptorParseFailed" || !has("SACLDescriptorParseFailed") {
			return conflict("sacl")
		}
	} else if has("SACLDescriptorParseFailed") {
		return conflict("sacl")
	}

	reparseReadError := observation.Reparse.DataState == records.ReparseDataStateError
	if reparseReadError != has("ReparseDataReadFailed") {
		return conflict("reparse")
	}

	reparseParseFailure := observation.Reparse.DataState == records.ReparseDataStatePresent &&
		observation.Reparse.DataFormat == records.ReparseDataFormatRaw &&
		observation.Reparse.ReasonCode == "ReparseDataParseFailed"
	if reparseParseFailure != has("ReparseDataParseFailed") {
		return conflict("reparse")
	}

	if observation.ContentHashes != nil && observation.ContentPrefix != nil {
		if err := validateContentObservationConsistency(observation); err != nil {
			return err
		}
	}

	contentHashFailure := observation.ContentHashes != nil &&
		observation.ContentHashes.State == records.ContentHashError
	if contentHashFailure != has("ContentHashFailed") {
		return conflict("content_hashes")
	}

	partialCondition := parentError || streamError || securityReadError || securityParseFailure ||
		saclReadError || saclParseFailure || reparseReadError || reparseParseFailure ||
		contentHashFailure || has("PathConsistencyNotVerified")

	switch observation.ObservationStatus {
	case records.ObservationComplete:
		if len(observation.Warnings) != 0 || partialCondition {
			return conflict("observation_status")
		}
	case records.ObservationChangedDuringCollection:
		if !has("MetadataChangedDuringCollection") || partialCondition || has("PathNowReferencesDifferentObject") {
			return conflict("observation_status")
		}
	case records.ObservationPartial:
		if !partialCondition {
			return conflict("observation_status")
		}
	case records.ObservationReplacedDuringCollection:
		if !has("PathNowReferencesDifferentObject") {
			return conflict("observation_status")
		}
	default:
		return &records.ValidationError{Code: "UnsupportedValue", Field: "observation_status"}
	}

	return nil
}

func validateContentObservationConsistency(observation Observation) error {
	conflict := func(field string) error {
		return &records.ValidationError{Code: "Conflict", Field: field}
	}

	hashes := *observation.ContentHashes
	prefix := *observation.ContentPrefix

	if observation.SubjectKind == records.SubjectDirectory || observation.Reparse.State == records.ReparseStatePresent {
		if hashes.State != records.ContentHashNotApplicable || prefix.State != records.ContentPrefixNotApplicable {
			return conflict("content_observation")
		}
		return nil
	}

	if observation.SubjectKind != records.SubjectFile || observation.Reparse.State != records.ReparseStateNotPresent {
		return conflict("content_observation")
	}

	switch hashes.State {
	case records.ContentHashNotApplicable:
		return conflict("content_hashes")

	case records.ContentHashError:
		if prefix.State != records.ContentPrefixError ||
			prefix.ReasonCode != hashes.ReasonCode ||
			prefix.Detail != hashes.Detail {
			return conflict("content_observation")
		}
		return nil

	case records.ContentHashPresent:
		if prefix.State != records.ContentPrefixPresent {
			return conflict("content_prefix")
		}
		bytesHashed, err := strconv.ParseUint(hashes.BytesHashed, 10, 64)
		if err != nil {
			return conflict("content_hashes.bytes_hashed")
		}
		bytesObserved, err := strconv.ParseUint(prefix.BytesObserved, 10, 64)
		if err != nil {
			return conflict("content_prefix.bytes_observed")
		}
		expected := bytesHashed
		if expected > records.ContentPrefixMaxBytes {
			expected = records.ContentPrefixMaxBytes
		}
		if bytesObserved != expected {
			return conflict("content_observation")
		}
		return nil

	default:
		return conflict("content_hashes.state")
	}
}
