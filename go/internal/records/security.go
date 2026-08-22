// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package records

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"reflect"
	"strconv"
)

// SecurityDataFormat records how FI represented a Windows security descriptor.
type SecurityDataFormat string

const (
	SecurityDataFormatInterpreted SecurityDataFormat = "Interpreted"
	SecurityDataFormatNotKnown    SecurityDataFormat = "NotKnown"
	SecurityDataFormatRaw         SecurityDataFormat = "Raw"
)

// ACLState preserves the materially different Windows DACL states.
type ACLState string

const (
	ACLStateNotPresent ACLState = "NotPresent"
	ACLStateNull       ACLState = "Null"
	ACLStatePresent    ACLState = "Present"
)

// SecurityObservation records the owner, primary group, DACL, and exact raw
// self-relative Windows security descriptor returned for one NTFS object.
//
// RawDescriptorBase64URL is authoritative. Interpreted fields are deterministic
// projections of the raw descriptor and are revalidated against it.
type SecurityObservation struct {
	State                  ObservationState   `json:"state"`
	DataFormat             SecurityDataFormat `json:"data_format"`
	RawDescriptorBase64URL string             `json:"raw_descriptor_base64url,omitempty"`
	Revision               string             `json:"revision,omitempty"`
	Control                string             `json:"control,omitempty"`
	OwnerSID               string             `json:"owner_sid,omitempty"`
	PrimaryGroupSID        string             `json:"primary_group_sid,omitempty"`
	DACL                   ACLObservation     `json:"dacl"`
	ReasonCode             string             `json:"reason_code,omitempty"`
}

// ACLObservation records the DACL state and, when present, its exact ordered
// ACE sequence. A Present ACL with zero ACEs is an empty DACL and is distinct
// from a Null DACL.
type ACLObservation struct {
	State    ACLState         `json:"state"`
	Revision string           `json:"revision,omitempty"`
	Size     string           `json:"size,omitempty"`
	ACEs     []ACEObservation `json:"aces"`
}

// ACEObservation preserves every ACE byte and the exact ACE header. FI
// interprets the access mask and SID only for ACE layouts it understands
// exactly; all other ACE types remain losslessly represented by RawBase64URL.
type ACEObservation struct {
	Index                   string `json:"index"`
	Type                    string `json:"type"`
	TypeName                string `json:"type_name"`
	Flags                   string `json:"flags"`
	Size                    string `json:"size"`
	RawBase64URL            string `json:"raw_base64url"`
	Mask                    string `json:"mask,omitempty"`
	ObjectFlags             string `json:"object_flags,omitempty"`
	ObjectTypeGUID          string `json:"object_type_guid,omitempty"`
	InheritedObjectTypeGUID string `json:"inherited_object_type_guid,omitempty"`
	SID                     string `json:"sid,omitempty"`
}

const (
	securityDescriptorRelativeHeaderSize = 20
	aclHeaderSize                        = 8
	aceHeaderSize                        = 4
	seDACLPresent                        = 0x0004
	seSelfRelative                       = 0x8000
	maxSIDSubAuthorities                 = 15
	aceObjectTypePresent                 = 0x00000001
	aceInheritedObjectTypePresent        = 0x00000002
	knownObjectACEFlags                  = aceObjectTypePresent | aceInheritedObjectTypePresent
)

// ParseSecurityDescriptor converts one exact self-relative Windows security
// descriptor into FI's shared representation.
func ParseSecurityDescriptor(raw []byte) (SecurityObservation, error) {
	parsed, err := parseSecurityDescriptor(raw)
	if err != nil {
		return SecurityObservation{}, err
	}
	parsed.RawDescriptorBase64URL = base64.RawURLEncoding.EncodeToString(raw)
	parsed.State = ObservationStatePresent
	parsed.DataFormat = SecurityDataFormatInterpreted
	return parsed, nil
}

// RawSecurityObservation preserves a security descriptor that FI obtained but
// could not interpret completely.
func RawSecurityObservation(raw []byte, reasonCode string) SecurityObservation {
	return SecurityObservation{
		State:                  ObservationStatePresent,
		DataFormat:             SecurityDataFormatRaw,
		RawDescriptorBase64URL: base64.RawURLEncoding.EncodeToString(raw),
		DACL:                   ACLObservation{ACEs: []ACEObservation{}},
		ReasonCode:             reasonCode,
	}
}

// SecurityObservationError records a non-fatal security collection failure.
func SecurityObservationError(reasonCode string) SecurityObservation {
	return SecurityObservation{
		State:      ObservationStateError,
		DataFormat: SecurityDataFormatNotKnown,
		DACL:       ACLObservation{ACEs: []ACEObservation{}},
		ReasonCode: reasonCode,
	}
}

// ValidateSecurityObservation validates both record shape and raw-to-interpreted
// consistency.
func ValidateSecurityObservation(observation SecurityObservation) error {
	switch observation.State {
	case ObservationStateError:
		if observation.DataFormat != SecurityDataFormatNotKnown || observation.ReasonCode == "" ||
			observation.RawDescriptorBase64URL != "" || observation.Revision != "" ||
			observation.Control != "" || observation.OwnerSID != "" || observation.PrimaryGroupSID != "" ||
			observation.DACL.State != "" || observation.DACL.Revision != "" || observation.DACL.Size != "" ||
			len(observation.DACL.ACEs) != 0 {
			return securityInvalid("Conflict", "security")
		}
		return nil

	case ObservationStatePresent:
		if observation.RawDescriptorBase64URL == "" {
			return securityInvalid("Required", "security.raw_descriptor_base64url")
		}
		raw, err := base64.RawURLEncoding.DecodeString(observation.RawDescriptorBase64URL)
		if err != nil || base64.RawURLEncoding.EncodeToString(raw) != observation.RawDescriptorBase64URL {
			return securityInvalid("InvalidEncoding", "security.raw_descriptor_base64url")
		}

		switch observation.DataFormat {
		case SecurityDataFormatRaw:
			if observation.ReasonCode == "" || observation.Revision != "" || observation.Control != "" ||
				observation.OwnerSID != "" || observation.PrimaryGroupSID != "" || observation.DACL.State != "" ||
				observation.DACL.Revision != "" || observation.DACL.Size != "" || len(observation.DACL.ACEs) != 0 {
				return securityInvalid("Conflict", "security")
			}
			return nil

		case SecurityDataFormatInterpreted:
			if observation.ReasonCode != "" {
				return securityInvalid("Conflict", "security.reason_code")
			}
			expected, err := ParseSecurityDescriptor(raw)
			if err != nil {
				return securityInvalid("MalformedRawData", "security.raw_descriptor_base64url")
			}
			if !reflect.DeepEqual(observation, expected) {
				return securityInvalid("Conflict", "security")
			}
			return nil

		default:
			return securityInvalid("UnsupportedValue", "security.data_format")
		}

	default:
		return securityInvalid("UnsupportedValue", "security.state")
	}
}

func parseSecurityDescriptor(raw []byte) (SecurityObservation, error) {
	if len(raw) < securityDescriptorRelativeHeaderSize {
		return SecurityObservation{}, fmt.Errorf("security descriptor shorter than relative header")
	}

	revision := raw[0]
	control := binary.LittleEndian.Uint16(raw[2:4])
	if control&seSelfRelative == 0 {
		return SecurityObservation{}, fmt.Errorf("security descriptor is not self-relative")
	}

	ownerOffset := binary.LittleEndian.Uint32(raw[4:8])
	groupOffset := binary.LittleEndian.Uint32(raw[8:12])
	daclOffset := binary.LittleEndian.Uint32(raw[16:20])

	ownerSID, err := sidAtOffset(raw, ownerOffset)
	if err != nil {
		return SecurityObservation{}, fmt.Errorf("owner SID: %w", err)
	}
	groupSID, err := sidAtOffset(raw, groupOffset)
	if err != nil {
		return SecurityObservation{}, fmt.Errorf("primary group SID: %w", err)
	}

	dacl, err := parseDACL(raw, control, daclOffset)
	if err != nil {
		return SecurityObservation{}, err
	}

	return SecurityObservation{
		Revision:        strconv.FormatUint(uint64(revision), 10),
		Control:         strconv.FormatUint(uint64(control), 10),
		OwnerSID:        ownerSID,
		PrimaryGroupSID: groupSID,
		DACL:            dacl,
	}, nil
}

func parseDACL(raw []byte, control uint16, offset uint32) (ACLObservation, error) {
	if control&seDACLPresent == 0 {
		if offset != 0 {
			return ACLObservation{}, fmt.Errorf("DACL offset present without SE_DACL_PRESENT")
		}
		return ACLObservation{State: ACLStateNotPresent, ACEs: []ACEObservation{}}, nil
	}
	if offset == 0 {
		return ACLObservation{State: ACLStateNull, ACEs: []ACEObservation{}}, nil
	}
	if offset < securityDescriptorRelativeHeaderSize || uint64(offset)+aclHeaderSize > uint64(len(raw)) {
		return ACLObservation{}, fmt.Errorf("DACL offset outside descriptor")
	}

	start := int(offset)
	aclSize := int(binary.LittleEndian.Uint16(raw[start+2 : start+4]))
	aceCount := int(binary.LittleEndian.Uint16(raw[start+4 : start+6]))
	if aclSize < aclHeaderSize || start+aclSize > len(raw) {
		return ACLObservation{}, fmt.Errorf("DACL size outside descriptor")
	}

	aclEnd := start + aclSize
	cursor := start + aclHeaderSize
	aces := make([]ACEObservation, 0, aceCount)
	for index := 0; index < aceCount; index++ {
		if cursor+aceHeaderSize > aclEnd {
			return ACLObservation{}, fmt.Errorf("ACE header outside DACL")
		}
		aceSize := int(binary.LittleEndian.Uint16(raw[cursor+2 : cursor+4]))
		if aceSize < aceHeaderSize || cursor+aceSize > aclEnd {
			return ACLObservation{}, fmt.Errorf("ACE size outside DACL")
		}
		ace, err := parseACE(index, raw[cursor:cursor+aceSize])
		if err != nil {
			return ACLObservation{}, err
		}
		aces = append(aces, ace)
		cursor += aceSize
	}

	return ACLObservation{
		State:    ACLStatePresent,
		Revision: strconv.FormatUint(uint64(raw[start]), 10),
		Size:     strconv.FormatUint(uint64(aclSize), 10),
		ACEs:     aces,
	}, nil
}

func parseACE(index int, raw []byte) (ACEObservation, error) {
	if len(raw) < aceHeaderSize {
		return ACEObservation{}, fmt.Errorf("ACE shorter than header")
	}

	aceType := raw[0]
	observation := ACEObservation{
		Index:        strconv.Itoa(index),
		Type:         strconv.FormatUint(uint64(aceType), 10),
		TypeName:     aceTypeName(aceType),
		Flags:        strconv.FormatUint(uint64(raw[1]), 10),
		Size:         strconv.Itoa(len(raw)),
		RawBase64URL: base64.RawURLEncoding.EncodeToString(raw),
	}

	// These ACE types share the exact ACE_HEADER, ACCESS_MASK, SID layout.
	// Callback ACEs are intentionally excluded because they may contain
	// application data after the SID and are preserved raw-only for now.
	switch aceType {
	case 0x00, 0x01, 0x02, 0x03, 0x11:
		if err := parseSimpleSIDACE(&observation, raw); err != nil {
			return ACEObservation{}, err
		}

	// ACCESS_ALLOWED_OBJECT_ACE, ACCESS_DENIED_OBJECT_ACE,
	// SYSTEM_AUDIT_OBJECT_ACE, and SYSTEM_ALARM_OBJECT_ACE share the same exact
	// object-ACE layout. Callback-object ACEs remain raw-only because they may
	// append application data after the SID.
	case 0x05, 0x06, 0x07, 0x08:
		if err := parseObjectACE(&observation, raw); err != nil {
			return ACEObservation{}, err
		}
	}

	return observation, nil
}

func parseSimpleSIDACE(observation *ACEObservation, raw []byte) error {
	if len(raw) < 8 {
		return fmt.Errorf("simple SID ACE shorter than mask/SID header")
	}
	sid, sidLength, err := sidFromBytes(raw[8:])
	if err != nil {
		return fmt.Errorf("ACE SID: %w", err)
	}
	if 8+sidLength != len(raw) {
		return fmt.Errorf("simple SID ACE contains trailing bytes")
	}
	observation.Mask = strconv.FormatUint(uint64(binary.LittleEndian.Uint32(raw[4:8])), 10)
	observation.SID = sid
	return nil
}

func parseObjectACE(observation *ACEObservation, raw []byte) error {
	if len(raw) < 12 {
		return fmt.Errorf("object ACE shorter than mask/object-flags header")
	}

	objectFlags := binary.LittleEndian.Uint32(raw[8:12])
	observation.Mask = strconv.FormatUint(uint64(binary.LittleEndian.Uint32(raw[4:8])), 10)
	observation.ObjectFlags = strconv.FormatUint(uint64(objectFlags), 10)

	// Unknown object-flag bits could change where later fields begin. Preserve
	// the exact ACE and fixed fields, but do not guess at GUID or SID offsets.
	if objectFlags&^uint32(knownObjectACEFlags) != 0 {
		return nil
	}

	cursor := 12
	if objectFlags&aceObjectTypePresent != 0 {
		if cursor+16 > len(raw) {
			return fmt.Errorf("object ACE ObjectType GUID outside ACE")
		}
		observation.ObjectTypeGUID = formatWindowsGUID(raw[cursor : cursor+16])
		cursor += 16
	}
	if objectFlags&aceInheritedObjectTypePresent != 0 {
		if cursor+16 > len(raw) {
			return fmt.Errorf("object ACE InheritedObjectType GUID outside ACE")
		}
		observation.InheritedObjectTypeGUID = formatWindowsGUID(raw[cursor : cursor+16])
		cursor += 16
	}

	sid, sidLength, err := sidFromBytes(raw[cursor:])
	if err != nil {
		return fmt.Errorf("object ACE SID: %w", err)
	}
	if cursor+sidLength != len(raw) {
		return fmt.Errorf("object ACE contains trailing bytes")
	}
	observation.SID = sid
	return nil
}

func formatWindowsGUID(raw []byte) string {
	return fmt.Sprintf(
		"%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		binary.LittleEndian.Uint32(raw[0:4]),
		binary.LittleEndian.Uint16(raw[4:6]),
		binary.LittleEndian.Uint16(raw[6:8]),
		raw[8],
		raw[9],
		raw[10],
		raw[11],
		raw[12],
		raw[13],
		raw[14],
		raw[15],
	)
}

func sidAtOffset(raw []byte, offset uint32) (string, error) {
	if offset == 0 {
		return "", nil
	}
	if offset < securityDescriptorRelativeHeaderSize || offset >= uint32(len(raw)) {
		return "", fmt.Errorf("SID offset outside descriptor")
	}
	sid, _, err := sidFromBytes(raw[int(offset):])
	return sid, err
}

func sidFromBytes(raw []byte) (string, int, error) {
	if len(raw) < 8 {
		return "", 0, fmt.Errorf("SID shorter than header")
	}
	count := int(raw[1])
	if count > maxSIDSubAuthorities {
		return "", 0, fmt.Errorf("SID sub-authority count exceeds Windows maximum")
	}
	length := 8 + count*4
	if length > len(raw) {
		return "", 0, fmt.Errorf("SID length outside buffer")
	}

	authority := uint64(0)
	for _, value := range raw[2:8] {
		authority = authority<<8 | uint64(value)
	}

	result := "S-" + strconv.FormatUint(uint64(raw[0]), 10) + "-" + strconv.FormatUint(authority, 10)
	for index := 0; index < count; index++ {
		start := 8 + index*4
		subAuthority := binary.LittleEndian.Uint32(raw[start : start+4])
		result += "-" + strconv.FormatUint(uint64(subAuthority), 10)
	}
	return result, length, nil
}

func aceTypeName(aceType byte) string {
	switch aceType {
	case 0x00:
		return "AccessAllowed"
	case 0x01:
		return "AccessDenied"
	case 0x02:
		return "SystemAudit"
	case 0x03:
		return "SystemAlarm"
	case 0x04:
		return "AccessAllowedCompound"
	case 0x05:
		return "AccessAllowedObject"
	case 0x06:
		return "AccessDeniedObject"
	case 0x07:
		return "SystemAuditObject"
	case 0x08:
		return "SystemAlarmObject"
	case 0x09:
		return "AccessAllowedCallback"
	case 0x0A:
		return "AccessDeniedCallback"
	case 0x0B:
		return "AccessAllowedCallbackObject"
	case 0x0C:
		return "AccessDeniedCallbackObject"
	case 0x0D:
		return "SystemAuditCallback"
	case 0x0E:
		return "SystemAlarmCallback"
	case 0x0F:
		return "SystemAuditCallbackObject"
	case 0x10:
		return "SystemAlarmCallbackObject"
	case 0x11:
		return "MandatoryLabel"
	case 0x12:
		return "ResourceAttribute"
	case 0x13:
		return "ScopedPolicyID"
	case 0x14:
		return "ProcessTrustLabel"
	case 0x15:
		return "AccessFilter"
	default:
		return "NotKnown"
	}
}

func securityInvalid(code, field string) error {
	return &ValidationError{Code: code, Field: field}
}
