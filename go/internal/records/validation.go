package records

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ValidationError provides one stable source-record validation failure identity.
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

func invalid(code, field string) error { return &ValidationError{Code: code, Field: field} }

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
	case ObservationStatePresent, ObservationStateNotApplicable, ObservationStateNotObserved,
		ObservationStateUnavailable, ObservationStateUnsupported, ObservationStateAccessDenied,
		ObservationStateAmbiguous, ObservationStateInvalid, ObservationStateError:
		return nil
	default:
		return invalid("UnsupportedValue", field)
	}
}

// ValidateVolumeIdentity validates one NTFS volume identity component.
func ValidateVolumeIdentity(identity VolumeIdentity) error {
	if err := require(identity.MethodVersion, "volume_identity.method_version"); err != nil {
		return err
	}
	if err := require(identity.VolumeGUID, "volume_identity.volume_guid"); err != nil {
		return err
	}
	return validateDecimal(identity.VolumeSerial, "volume_identity.volume_serial")
}

// ValidateNTFSObjectIdentity validates one NTFS object identity component.
func ValidateNTFSObjectIdentity(identity NTFSObjectIdentity) error {
	if err := require(identity.MethodVersion, "object_identity.method_version"); err != nil {
		return err
	}
	if err := validateDecimal(identity.FileReferenceNumber, "object_identity.file_reference_number"); err != nil {
		return err
	}
	if err := validateDecimal(identity.SequenceNumber, "object_identity.sequence_number"); err != nil {
		return err
	}
	switch identity.Confidence {
	case IdentityAuthoritative, IdentityCorroborated, IdentityAmbiguous,
		IdentityUnavailable, IdentityUnsupported, IdentityInvalid:
		return nil
	default:
		return invalid("UnsupportedValue", "object_identity.confidence")
	}
}

// ValidateGovernedRootIdentity validates one governed source-root identity.
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
	if err := require(root.MethodVersion, "governed_root.method_version"); err != nil {
		return err
	}
	if err := validateObservationState(root.State, "governed_root.state"); err != nil {
		return err
	}
	if root.State == ObservationStatePresent {
		if err := require(root.ResolvedPathUTF16LEBase64URL, "governed_root.resolved_path_utf16le_base64url"); err != nil {
			return err
		}
		if err := validateUTF16LEBase64URL(root.ResolvedPathUTF16LEBase64URL, "governed_root.resolved_path_utf16le_base64url"); err != nil {
			return err
		}
		if root.VolumeIdentity == nil || root.ObjectIdentity == nil {
			return invalid("IdentityMissing", "governed_root")
		}
		if err := ValidateVolumeIdentity(*root.VolumeIdentity); err != nil {
			return err
		}
		if err := ValidateNTFSObjectIdentity(*root.ObjectIdentity); err != nil {
			return err
		}
		if root.ReasonCode != "" {
			return invalid("Conflict", "governed_root.reason_code")
		}
		return nil
	}
	if root.ReasonCode == "" {
		return invalid("Required", "governed_root.reason_code")
	}
	if root.ResolvedPathUTF16LEBase64URL != "" || root.VolumeIdentity != nil || root.ObjectIdentity != nil {
		return invalid("Conflict", "governed_root")
	}
	return nil
}

// ValidatePathContainment validates one handle-derived scope conclusion.
func ValidatePathContainment(containment PathContainment) error {
	if err := require(containment.MethodVersion, "containment.method_version"); err != nil {
		return err
	}
	if err := validateObservationState(containment.State, "containment.state"); err != nil {
		return err
	}
	if containment.State == ObservationStatePresent {
		if containment.ReasonCode != "" {
			return invalid("Conflict", "containment.reason_code")
		}
		return nil
	}
	if containment.ReasonCode == "" {
		return invalid("Required", "containment.reason_code")
	}
	return nil
}

// ValidateSubjectKind validates one NTFS subject-kind value.
func ValidateSubjectKind(kind SubjectKind) error {
	switch kind {
	case SubjectFile, SubjectDirectory, SubjectReparseObject:
		return nil
	default:
		return invalid("UnsupportedValue", "subject_kind")
	}
}

// ValidatePathBinding validates one exact UTF-16LE path binding.
func ValidatePathBinding(binding PathBinding) error {
	if binding.PathUTF16LEBase64URL == "" {
		return invalid("Required", "path_binding.path_utf16le_base64url")
	}
	if err := validateUTF16LEBase64URL(binding.PathUTF16LEBase64URL, "path_binding.path_utf16le_base64url"); err != nil {
		return err
	}
	if err := validateObservationState(binding.State, "path_binding.state"); err != nil {
		return err
	}
	if binding.ParentObject != nil {
		return ValidateNTFSObjectIdentity(*binding.ParentObject)
	}
	return nil
}

// ValidateMetadataObservation validates bounded NTFS metadata.
func ValidateMetadataObservation(metadata MetadataObservation) error {
	if err := validateObservationState(metadata.State, "metadata.state"); err != nil {
		return err
	}
	if metadata.State != ObservationStatePresent {
		if metadata.ReasonCode == "" {
			return invalid("Required", "metadata.reason_code")
		}
		return nil
	}
	if metadata.ObjectKind == "" {
		return invalid("Required", "metadata.object_kind")
	}
	for field, value := range map[string]string{
		"metadata.logical_size": metadata.LogicalSize, "metadata.allocated_size": metadata.AllocatedSize,
		"metadata.raw_attributes": metadata.RawAttributes, "metadata.link_count": metadata.LinkCount,
	} {
		if err := validateDecimal(value, field); err != nil {
			return err
		}
	}
	for field, value := range map[string]string{
		"metadata.creation_time": metadata.CreationTime, "metadata.last_write_time": metadata.LastWriteTime,
		"metadata.change_time": metadata.ChangeTime, "metadata.last_access_time": metadata.LastAccessTime,
	} {
		if err := validateTimestamp(value, field); err != nil {
			return err
		}
	}
	return nil
}

// ValidateStreamIdentity validates exact NTFS stream identity fields.
func ValidateStreamIdentity(identity StreamIdentity) error {
	if identity.RawNameUTF16LEBase64URL == "" {
		return invalid("Required", "stream_identity.raw_name_utf16le_base64url")
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
		if identity.NameUTF16LEBase64URL == "" {
			return invalid("Required", "stream_identity.name_utf16le_base64url")
		}
		if err := validateUTF16LEBase64URL(identity.NameUTF16LEBase64URL, "stream_identity.name_utf16le_base64url"); err != nil {
			return err
		}
		if identity.StreamType == "" {
			return invalid("Required", "stream_identity.stream_type")
		}
	default:
		return invalid("UnsupportedValue", "stream_identity.kind")
	}
	return nil
}

// ValidateStreamInventory validates stream enumeration and stable ordering.
func ValidateStreamInventory(inventory StreamInventory) error {
	if err := validateObservationState(inventory.State, "stream_inventory.state"); err != nil {
		return err
	}
	if inventory.State != ObservationStatePresent {
		if inventory.ReasonCode == "" {
			return invalid("Required", "stream_inventory.reason_code")
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
		if err := validateObservationState(stream.State, fmt.Sprintf("stream_inventory.streams[%d].state", i)); err != nil {
			return err
		}
		if stream.State != ObservationStatePresent {
			if stream.ReasonCode == "" {
				return invalid("Required", fmt.Sprintf("stream_inventory.streams[%d].reason_code", i))
			}
			continue
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

// ValidateObservationStatus validates one whole-observation status.
func ValidateObservationStatus(status ObservationStatus) error {
	switch status {
	case ObservationComplete, ObservationPartial, ObservationChangedDuringCollection,
		ObservationReplacedDuringCollection, ObservationSubjectNotFound,
		ObservationSourceUnavailable, ObservationContinuityLost, ObservationInvalid,
		ObservationCancelled:
		return nil
	default:
		return invalid("UnsupportedValue", "observation_status")
	}
}

// ValidateObservationWarnings validates stable sorted warning identities.
func ValidateObservationWarnings(warnings []ObservationWarning) error {
	previous := ""
	for i, warning := range warnings {
		if warning.Code == "" {
			return invalid("Required", fmt.Sprintf("warnings[%d].code", i))
		}
		if previous != "" && warning.Code <= previous {
			return invalid("UnsortedCollection", "warnings")
		}
		previous = warning.Code
	}
	return nil
}
