// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package records

import (
	"encoding/base64"
	"encoding/binary"
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

const (
	maxNTFSFileReferenceNumber uint64 = 0x0000FFFFFFFFFFFF
	maxNTFSSequenceNumber      uint64 = 0xFFFF
)

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

// ValidateNTFSObjectIdentity validates a shared NTFS object identity.
func ValidateNTFSObjectIdentity(identity NTFSObjectIdentity) error {
	if err := require(identity.MethodVersion, "object_identity.method_version"); err != nil {
		return err
	}
	if err := validateDecimalMax(identity.FileReferenceNumber, maxNTFSFileReferenceNumber, "object_identity.file_reference_number"); err != nil {
		return err
	}
	return validateDecimalMax(identity.SequenceNumber, maxNTFSSequenceNumber, "object_identity.sequence_number")
}

// ValidateObservedAt validates the canonical UTC time when FI completed the
// source observation.
func ValidateObservedAt(value string) error {
	return validateTimestamp(value, "observed_at")
}

// ValidateObservationStatus validates the statuses the current NTFS collector
// can actually emit.
func ValidateObservationStatus(status ObservationStatus) error {
	switch status {
	case ObservationChangedDuringCollection, ObservationComplete, ObservationPartial,
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

// ValidatePathBinding validates the exact requested and resolved UTF-16LE path
// representations.
func ValidatePathBinding(binding PathBinding) error {
	if err := require(binding.RequestedPathUTF16LEBase64URL, "path_binding.requested_path_utf16le_base64url"); err != nil {
		return err
	}
	if err := validateUTF16LEBase64URL(binding.RequestedPathUTF16LEBase64URL, "path_binding.requested_path_utf16le_base64url"); err != nil {
		return err
	}
	if err := require(binding.ResolvedPathUTF16LEBase64URL, "path_binding.resolved_path_utf16le_base64url"); err != nil {
		return err
	}
	return validateUTF16LEBase64URL(binding.ResolvedPathUTF16LEBase64URL, "path_binding.resolved_path_utf16le_base64url")
}

// ValidatePathContainment validates the recorded containment method.
func ValidatePathContainment(containment PathContainment) error {
	return require(containment.MethodVersion, "containment.method_version")
}

// ValidateReparseObservation validates both the shape and the internal
// consistency of the shared Windows reparse representation. For documented
// layouts FI understands, parsed fields must exactly match the preserved raw
// reparse buffer.
func ValidateReparseObservation(reparse ReparseObservation) error {
	switch reparse.State {
	case ReparseStateNotPresent:
		if reparse.DataFormat != ReparseDataFormatNotApplicable ||
			reparse.DataState != ReparseDataStateNotApplicable ||
			reparse.PrintNameUTF16LEBase64URL != "" ||
			reparse.RawBufferBase64URL != "" ||
			reparse.ReasonCode != "" ||
			reparse.SubstituteNameUTF16LEBase64URL != "" ||
			reparse.SymbolicLinkFlags != "" ||
			reparse.Tag != "" ||
			reparse.TagName != "" {
			return invalid("Conflict", "reparse")
		}
		return nil

	case ReparseStatePresent:
		if err := validateReparseTag(reparse.Tag, "reparse.tag"); err != nil {
			return err
		}
		if reparse.TagName != ReparseTagName(reparse.Tag) {
			return invalid("Conflict", "reparse.tag_name")
		}

		switch reparse.DataState {
		case ReparseDataStateError:
			if reparse.DataFormat != ReparseDataFormatNotKnown {
				return invalid("Conflict", "reparse.data_format")
			}
			if err := require(reparse.ReasonCode, "reparse.reason_code"); err != nil {
				return err
			}
			if reparse.PrintNameUTF16LEBase64URL != "" ||
				reparse.RawBufferBase64URL != "" ||
				reparse.SubstituteNameUTF16LEBase64URL != "" ||
				reparse.SymbolicLinkFlags != "" {
				return invalid("Conflict", "reparse")
			}
			return nil

		case ReparseDataStateNotApplicable:
			return invalid("Conflict", "reparse.data_state")

		case ReparseDataStatePresent:
			if err := require(reparse.RawBufferBase64URL, "reparse.raw_buffer_base64url"); err != nil {
				return err
			}
			raw, err := decodeBase64URL(reparse.RawBufferBase64URL, "reparse.raw_buffer_base64url")
			if err != nil {
				return err
			}
			if len(raw) < 8 {
				return invalid("InvalidReparseBuffer", "reparse.raw_buffer_base64url")
			}
			rawTag := fmt.Sprintf("0x%08X", binary.LittleEndian.Uint32(raw[0:4]))
			if rawTag != reparse.Tag {
				return invalid("Conflict", "reparse.raw_buffer_base64url")
			}

			switch reparse.DataFormat {
			case ReparseDataFormatMountPoint:
				if reparse.Tag != reparseTagMountPointCanonical || reparse.SymbolicLinkFlags != "" || reparse.ReasonCode != "" {
					return invalid("Conflict", "reparse.data_format")
				}
			case ReparseDataFormatRaw:
				if reparse.PrintNameUTF16LEBase64URL != "" ||
					reparse.SubstituteNameUTF16LEBase64URL != "" ||
					reparse.SymbolicLinkFlags != "" {
					return invalid("Conflict", "reparse")
				}
			case ReparseDataFormatSymbolicLink:
				if reparse.Tag != reparseTagSymlinkCanonical || reparse.ReasonCode != "" {
					return invalid("Conflict", "reparse.data_format")
				}
				if err := require(reparse.SymbolicLinkFlags, "reparse.symbolic_link_flags"); err != nil {
					return err
				}
			case ReparseDataFormatNotApplicable, ReparseDataFormatNotKnown:
				return invalid("Conflict", "reparse.data_format")
			default:
				return invalid("UnsupportedValue", "reparse.data_format")
			}
			return validateReparsePayloadConsistency(reparse, raw)

		default:
			return invalid("UnsupportedValue", "reparse.data_state")
		}

	default:
		return invalid("UnsupportedValue", "reparse.state")
	}
}

// ValidateStreamIdentity validates the exact NTFS stream identity and proves
// that every interpreted field is the deterministic projection of the raw
// UTF-16 stream name.
func ValidateStreamIdentity(identity StreamIdentity) error {
	if err := require(identity.RawNameUTF16LEBase64URL, "stream_identity.raw_name_utf16le_base64url"); err != nil {
		return err
	}
	rawUnits, err := decodeUTF16LEBase64URLUnits(identity.RawNameUTF16LEBase64URL, "stream_identity.raw_name_utf16le_base64url")
	if err != nil {
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

	expected := StreamIdentityFromRawUTF16(rawUnits)
	if identity != expected {
		return invalid("Conflict", "stream_identity")
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

// ValidateSubjectKind validates the base NTFS object kind emitted by the
// collector. Reparse state is validated separately.
func ValidateSubjectKind(kind SubjectKind) error {
	switch kind {
	case SubjectDirectory, SubjectFile:
		return nil
	default:
		return invalid("UnsupportedValue", "subject_kind")
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
	if err := validateVolumeGUIDPath(identity.VolumeGUID, "volume_identity.volume_guid"); err != nil {
		return err
	}
	return validateDecimal(identity.VolumeSerial, "volume_identity.volume_serial")
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

func decodeUTF16LEBase64URLUnits(value, field string) ([]uint16, error) {
	decoded, err := decodeBase64URL(value, field)
	if err != nil {
		return nil, err
	}
	if len(decoded)%2 != 0 {
		return nil, invalid("InvalidUTF16LE", field)
	}
	units := make([]uint16, len(decoded)/2)
	for index := range units {
		units[index] = binary.LittleEndian.Uint16(decoded[index*2:])
	}
	return units, nil
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

func validateDecimal(value, field string) error {
	if _, err := canonicalUnsigned(value); err != nil {
		return invalid("InvalidDecimal", field)
	}
	return nil
}

func validateDecimalMax(value string, maximum uint64, field string) error {
	parsed, err := canonicalUnsigned(value)
	if err != nil {
		return invalid("InvalidDecimal", field)
	}
	if parsed > maximum {
		return invalid("OutOfRange", field)
	}
	return nil
}

func validateHex32(value, field string) error {
	if len(value) != 10 || value[0:2] != "0x" {
		return invalid("InvalidHex32", field)
	}
	for _, character := range value[2:] {
		switch {
		case character >= '0' && character <= '9':
		case character >= 'A' && character <= 'F':
		default:
			return invalid("InvalidHex32", field)
		}
	}
	return nil
}

func validateObservationState(state ObservationState, field string) error {
	switch state {
	case ObservationStateError, ObservationStatePresent:
		return nil
	default:
		return invalid("UnsupportedValue", field)
	}
}

func validateReparseTag(value, field string) error {
	if err := validateHex32(value, field); err != nil {
		return invalid("InvalidReparseTag", field)
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

func validateUTF16LEBase64URL(value, field string) error {
	_, err := decodeUTF16LEBase64URLUnits(value, field)
	return err
}

func validateVolumeGUIDPath(value, field string) error {
	const prefix = `\\?\Volume{`
	if !strings.HasPrefix(value, prefix) || !strings.HasSuffix(value, `}\`) {
		return invalid("InvalidVolumeGUID", field)
	}
	guid := value[len(prefix) : len(value)-2]
	if len(guid) != 36 {
		return invalid("InvalidVolumeGUID", field)
	}
	for index, character := range guid {
		switch index {
		case 8, 13, 18, 23:
			if character != '-' {
				return invalid("InvalidVolumeGUID", field)
			}
		default:
			if !((character >= '0' && character <= '9') ||
				(character >= 'a' && character <= 'f') ||
				(character >= 'A' && character <= 'F')) {
				return invalid("InvalidVolumeGUID", field)
			}
		}
	}
	return nil
}

// END Used by Windows Systems and Backend Recorder.
