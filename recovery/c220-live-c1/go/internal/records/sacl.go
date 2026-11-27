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

const seSACLPresent = 0x0010

// SACLObservation records the exact self-relative descriptor returned by a
// SACL-only Windows security query and the interpreted system ACL within it.
//
// RawDescriptorBase64URL is authoritative when State is Present. The ACL is a
// deterministic projection of that raw descriptor and is revalidated against
// it. A collection error is distinct from an observed descriptor with no SACL.
type SACLObservation struct {
	State                  ObservationState   `json:"state"`
	DataFormat             SecurityDataFormat `json:"data_format"`
	RawDescriptorBase64URL string             `json:"raw_descriptor_base64url,omitempty"`
	Revision               string             `json:"revision,omitempty"`
	Control                string             `json:"control,omitempty"`
	ACL                    ACLObservation     `json:"acl"`
	ReasonCode             string             `json:"reason_code,omitempty"`
}

// ParseSACLDescriptor converts one exact self-relative Windows descriptor
// returned from a SACL query into FI's SACL representation.
func ParseSACLDescriptor(raw []byte) (SACLObservation, error) {
	parsed, err := parseSACLDescriptor(raw)
	if err != nil {
		return SACLObservation{}, err
	}
	parsed.RawDescriptorBase64URL = base64.RawURLEncoding.EncodeToString(raw)
	parsed.State = ObservationStatePresent
	parsed.DataFormat = SecurityDataFormatInterpreted
	return parsed, nil
}

// RawSACLObservation preserves a descriptor FI obtained but could not fully
// interpret.
func RawSACLObservation(raw []byte, reasonCode string) SACLObservation {
	return SACLObservation{
		State:                  ObservationStatePresent,
		DataFormat:             SecurityDataFormatRaw,
		RawDescriptorBase64URL: base64.RawURLEncoding.EncodeToString(raw),
		ACL:                    ACLObservation{ACEs: []ACEObservation{}},
		ReasonCode:             reasonCode,
	}
}

// SACLObservationError records a non-fatal SACL collection failure.
func SACLObservationError(reasonCode string) SACLObservation {
	return SACLObservation{
		State:      ObservationStateError,
		DataFormat: SecurityDataFormatNotKnown,
		ACL:        ACLObservation{ACEs: []ACEObservation{}},
		ReasonCode: reasonCode,
	}
}

// ValidateSACLObservation validates record shape and exact raw-to-interpreted
// consistency.
func ValidateSACLObservation(observation SACLObservation) error {
	switch observation.State {
	case ObservationStateError:
		if observation.DataFormat != SecurityDataFormatNotKnown || observation.ReasonCode == "" ||
			observation.RawDescriptorBase64URL != "" || observation.Revision != "" ||
			observation.Control != "" || observation.ACL.State != "" ||
			observation.ACL.Revision != "" || observation.ACL.Size != "" || len(observation.ACL.ACEs) != 0 {
			return securityInvalid("Conflict", "sacl")
		}
		return nil

	case ObservationStatePresent:
		if observation.RawDescriptorBase64URL == "" {
			return securityInvalid("Required", "sacl.raw_descriptor_base64url")
		}
		raw, err := base64.RawURLEncoding.DecodeString(observation.RawDescriptorBase64URL)
		if err != nil || base64.RawURLEncoding.EncodeToString(raw) != observation.RawDescriptorBase64URL {
			return securityInvalid("InvalidEncoding", "sacl.raw_descriptor_base64url")
		}

		switch observation.DataFormat {
		case SecurityDataFormatRaw:
			if observation.ReasonCode == "" || observation.Revision != "" || observation.Control != "" ||
				observation.ACL.State != "" || observation.ACL.Revision != "" || observation.ACL.Size != "" ||
				len(observation.ACL.ACEs) != 0 {
				return securityInvalid("Conflict", "sacl")
			}
			return nil

		case SecurityDataFormatInterpreted:
			if observation.ReasonCode != "" {
				return securityInvalid("Conflict", "sacl.reason_code")
			}
			expected, err := ParseSACLDescriptor(raw)
			if err != nil {
				return securityInvalid("MalformedRawData", "sacl.raw_descriptor_base64url")
			}
			if !reflect.DeepEqual(observation, expected) {
				return securityInvalid("Conflict", "sacl")
			}
			return nil

		default:
			return securityInvalid("UnsupportedValue", "sacl.data_format")
		}

	default:
		return securityInvalid("UnsupportedValue", "sacl.state")
	}
}

func parseSACLDescriptor(raw []byte) (SACLObservation, error) {
	if len(raw) < securityDescriptorRelativeHeaderSize {
		return SACLObservation{}, fmt.Errorf("security descriptor shorter than relative header")
	}

	revision := raw[0]
	control := binary.LittleEndian.Uint16(raw[2:4])
	if control&seSelfRelative == 0 {
		return SACLObservation{}, fmt.Errorf("security descriptor is not self-relative")
	}

	saclOffset := binary.LittleEndian.Uint32(raw[12:16])
	sacl, err := parseSACL(raw, control, saclOffset)
	if err != nil {
		return SACLObservation{}, err
	}

	return SACLObservation{
		Revision: strconv.FormatUint(uint64(revision), 10),
		Control:  strconv.FormatUint(uint64(control), 10),
		ACL:      sacl,
	}, nil
}

func parseSACL(raw []byte, control uint16, offset uint32) (ACLObservation, error) {
	if control&seSACLPresent == 0 {
		if offset != 0 {
			return ACLObservation{}, fmt.Errorf("SACL offset present without SE_SACL_PRESENT")
		}
		return ACLObservation{State: ACLStateNotPresent, ACEs: []ACEObservation{}}, nil
	}
	if offset == 0 {
		return ACLObservation{State: ACLStateNull, ACEs: []ACEObservation{}}, nil
	}
	if offset < securityDescriptorRelativeHeaderSize || uint64(offset)+aclHeaderSize > uint64(len(raw)) {
		return ACLObservation{}, fmt.Errorf("SACL offset outside descriptor")
	}

	start := int(offset)
	aclSize := int(binary.LittleEndian.Uint16(raw[start+2 : start+4]))
	aceCount := int(binary.LittleEndian.Uint16(raw[start+4 : start+6]))
	if aclSize < aclHeaderSize || start+aclSize > len(raw) {
		return ACLObservation{}, fmt.Errorf("SACL size outside descriptor")
	}

	aclEnd := start + aclSize
	cursor := start + aclHeaderSize
	aces := make([]ACEObservation, 0, aceCount)
	for index := 0; index < aceCount; index++ {
		if cursor+aceHeaderSize > aclEnd {
			return ACLObservation{}, fmt.Errorf("ACE header outside SACL")
		}
		aceSize := int(binary.LittleEndian.Uint16(raw[cursor+2 : cursor+4]))
		if aceSize < aceHeaderSize || cursor+aceSize > aclEnd {
			return ACLObservation{}, fmt.Errorf("ACE size outside SACL")
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
