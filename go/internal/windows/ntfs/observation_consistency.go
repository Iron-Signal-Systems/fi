// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package ntfs

import "github.com/Iron-Signal-Systems/fi/go/internal/records"

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

	streamError := observation.StreamInventory.State == records.ObservationStateError
	if streamError != has("StreamEnumerationFailed") {
		return conflict("stream_inventory")
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

	partialCondition := streamError || reparseReadError || reparseParseFailure || has("PathConsistencyNotVerified")

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
