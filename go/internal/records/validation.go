// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package records

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Used by Windows Systems and Backend Recorder.
//
// Windows runs these checks before a source observation leaves the collection
// boundary for record/staging work. Backend components can run the same checks
// after receiving a record.
//
// These checks validate the shared record representation. They do not repeat
// Windows API safety checks, which belong under internal/windows.

// ValidationError gives a stable validation code and field name.
type ValidationError struct {
	Code  string
	Field string
}

func (e *ValidationError) Error() string {
	if e.Field == "" {
		return e.Code
	}
	return e.Code + ": " + e.Field
}

func invalid(code, field string) error {
	return &ValidationError{Code: code, Field: field}
}

func require(value, field string) error {
	if value == "" {
		return invalid("Required", field)
	}
	return nil
}

func canonicalUnsigned(value string) (uint64, error) {
	if value == "0" {
		return 0, nil
	}
	if value == "" || value[0] < '1' || value[0] > '9' {
		return 0, errors.New("not canonical unsigned decimal")
	}
	for i := 1; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return 0, errors.New("not canonical unsigned decimal")
		}
	}
	return strconv.ParseUint(value, 10, 64)
}

func validateDecimal(value, field string) error {
	if _, err := canonicalUnsigned(value); err != nil {
		return invalid("InvalidDecimal", field)
	}
	return nil
}

func validateTimestamp(value, field string) error {
	const layout = "2006-01-02T15:04:05.000000000Z"
	if len(value) != len(layout) {
		return invalid("InvalidTimestamp", field)
	}
	parsed, err := time.Parse(layout, value)
	if err != nil || parsed.Format(layout) != value {
		return invalid("InvalidTimestamp", field)
	}
	return nil
}

func decodeBase64URL(value, field string) ([]byte, error) {
	if strings.ContainsAny(value, "=+/ \t\r\n") {
		return nil, invalid("InvalidBase64URL", field)
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, invalid("InvalidBase64URL", field)
	}
	return decoded, nil
}

func validateUTF16LEBase64URL(value, field string) error {
	decoded, err := decodeBase64URL(value, field)
	if err != nil {
		return err
	}
	if len(decoded)%2 != 0 {
		return invalid("InvalidUTF16LE", field)
	}
	return nil
}

func validateObservationState(state ObservationState, field string) error {
	switch state {
	case ObservationStatePresent, ObservationStateError:
		return nil
	default:
		return invalid("UnsupportedValue", field)
	}
}

// ValidateVolumeIdentity validates a shared NTFS volume identity.
func ValidateVolumeIdentity(identity VolumeIdentity) error {
	if err := require(identity.MethodVersion, "volume_identity.method_version"); err != nil {
		return err
	}
	if err := require(identity.VolumeGUID, "volume_identity.volume_guid"); err != nil {
		return err
	}
	return validateDecimal(identity.VolumeSerial, "volume_identity.volume_serial")
}

// ValidateNTFSObjectIdentity validates a shared NTFS object identity.
func ValidateNTFSObjectIdentity(identity NTFSObjectIdentity) error {
	if err := require(identity.MethodVersion, "object_identity.method_version"); err != nil {
		return err
	}
	if err := validateDecimal(identity.FileReferenceNumber, "object_identity.file_reference_number"); err != nil {
		return err
	}
	return validateDecimal(identity.SequenceNumber, "object_identity.sequence_number")
}

// ValidateGovernedRootIdentity validates the established governed root.
func ValidateGovernedRootIdentity(root GovernedRootIdentity) error {
	if err := require(root.ScopeID, "governed_root.scope_id"); err != nil {
		return err
	}
	if err := require(root.RequestedPathUTF16LEBase64URL, "governed_root.requested_path_utf16le_base64url"); err != nil {
		return err
	}
	if err := validateUTF16LEBase64URL(root.RequestedPathUTF16LEBase64URL, "governed_root.requested_path_utf16le_base64url"); err != nil {
		return err
	}
	if err := require(root.ResolvedPathUTF16LEBase64URL, "governed_root.resolved_path_utf16le_base64url"); err != nil {
		return err
	}
	if err := validateUTF16LEBase64URL(root.ResolvedPathUTF16LEBase64URL, "governed_root.resolved_path_utf16le_base64url"); err != nil {
		return err
	}
	if err := require(root.MethodVersion, "governed_root.method_version"); err != nil {
		return err
	}
	if err := ValidateVolumeIdentity(root.VolumeIdentity); err != nil {
		return err
	}
	return ValidateNTFSObjectIdentity(root.ObjectIdentity)
}

// ValidatePathContainment validates the recorded containment method.
func ValidatePathContainment(containment PathContainment) error {
	return require(containment.MethodVersion, "containment.method_version")
}

// ValidateSubjectKind validates the NTFS object kind emitted by the collector.
func ValidateSubjectKind(kind SubjectKind) error {
	switch kind {
	case SubjectFile, SubjectDirectory, SubjectReparseObject:
		return nil
	default:
		return invalid("UnsupportedValue", "subject_kind")
	}
}

// ValidatePathBinding validates the exact UTF-16LE path representation.
func ValidatePathBinding(binding PathBinding) error {
	if err := require(binding.PathUTF16LEBase64URL, "path_binding.path_utf16le_base64url"); err != nil {
		return err
	}
	return validateUTF16LEBase64URL(binding.PathUTF16LEBase64URL, "path_binding.path_utf16le_base64url")
}

// ValidateMetadataObservation validates canonical metadata values in a fixed
// order so the first reported error is deterministic.
func ValidateMetadataObservation(metadata MetadataObservation) error {
	decimals := []struct {
		field string
		value string
	}{
		{"metadata.logical_size", metadata.LogicalSize},
		{"metadata.allocated_size", metadata.AllocatedSize},
		{"metadata.raw_attributes", metadata.RawAttributes},
		{"metadata.link_count", metadata.LinkCount},
	}
	for _, item := range decimals {
		if err := validateDecimal(item.value, item.field); err != nil {
			return err
		}
	}

	timestamps := []struct {
		field string
		value string
	}{
		{"metadata.creation_time", metadata.CreationTime},
		{"metadata.last_write_time", metadata.LastWriteTime},
		{"metadata.change_time", metadata.ChangeTime},
		{"metadata.last_access_time", metadata.LastAccessTime},
	}
	for _, item := range timestamps {
		if err := validateTimestamp(item.value, item.field); err != nil {
			return err
		}
	}
	return nil
}

// ValidateStreamIdentity validates the exact NTFS stream identity.
func ValidateStreamIdentity(identity StreamIdentity) error {
	if err := require(identity.RawNameUTF16LEBase64URL, "stream_identity.raw_name_utf16le_base64url"); err != nil {
		return err
	}
	if err := validateUTF16LEBase64URL(identity.RawNameUTF16LEBase64URL, "stream_identity.raw_name_utf16le_base64url"); err != nil {
		return err
	}

	switch identity.Kind {
	case StreamDefaultData:
		if identity.NameUTF16LEBase64URL != "" || identity.StreamType != "$DATA" {
			return invalid("Conflict", "stream_identity")
		}
	case StreamNamedData, StreamOther:
		if err := require(identity.NameUTF16LEBase64URL, "stream_identity.name_utf16le_base64url"); err != nil {
			return err
		}
		if err := validateUTF16LEBase64URL(identity.NameUTF16LEBase64URL, "stream_identity.name_utf16le_base64url"); err != nil {
			return err
		}
		if err := require(identity.StreamType, "stream_identity.stream_type"); err != nil {
			return err
		}
	default:
		return invalid("UnsupportedValue", "stream_identity.kind")
	}
	return nil
}

// ValidateStreamInventory validates stream-enumeration state and ordering.
func ValidateStreamInventory(inventory StreamInventory) error {
	if err := validateObservationState(inventory.State, "stream_inventory.state"); err != nil {
		return err
	}

	if inventory.State == ObservationStateError {
		if err := require(inventory.ReasonCode, "stream_inventory.reason_code"); err != nil {
			return err
		}
		if len(inventory.Streams) != 0 {
			return invalid("Conflict", "stream_inventory.streams")
		}
		return nil
	}

	if inventory.ReasonCode != "" {
		return invalid("Conflict", "stream_inventory.reason_code")
	}

	previous := ""
	for i, stream := range inventory.Streams {
		if err := ValidateStreamIdentity(stream.Identity); err != nil {
			return err
		}
		if err := validateDecimal(stream.LogicalSize, fmt.Sprintf("stream_inventory.streams[%d].logical_size", i)); err != nil {
			return err
		}
		if err := validateDecimal(stream.AllocatedSize, fmt.Sprintf("stream_inventory.streams[%d].allocated_size", i)); err != nil {
			return err
		}
		key := stream.Identity.RawNameUTF16LEBase64URL
		if previous != "" && key <= previous {
			return invalid("UnsortedCollection", "stream_inventory.streams")
		}
		previous = key
	}
	return nil
}

// ValidateObservationStatus validates the statuses the current NTFS collector
// can actually emit.
func ValidateObservationStatus(status ObservationStatus) error {
	switch status {
	case ObservationComplete, ObservationPartial, ObservationChangedDuringCollection,
		ObservationReplacedDuringCollection:
		return nil
	default:
		return invalid("UnsupportedValue", "observation_status")
	}
}

// ValidateObservationWarnings validates stable warning identities and ordering.
func ValidateObservationWarnings(warnings []ObservationWarning) error {
	previous := ""
	for i, warning := range warnings {
		if err := require(warning.Code, fmt.Sprintf("warnings[%d].code", i)); err != nil {
			return err
		}
		if previous != "" && warning.Code <= previous {
			return invalid("UnsortedCollection", "warnings")
		}
		previous = warning.Code
	}
	return nil
}

// END Used by Windows Systems and Backend Recorder.
