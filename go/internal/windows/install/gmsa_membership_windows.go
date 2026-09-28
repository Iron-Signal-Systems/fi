// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"fmt"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// msDS-GroupMSAMembership is an NT security descriptor used by Active Directory
// when deciding whether a requester may retrieve a gMSA password. A trustee is
// treated as a simple password-retrieval principal only when its ACE is a
// standard ACCESS_ALLOWED_ACE that includes ADS_RIGHT_DS_READ_PROP.
//
// ADS_RIGHT_DS_READ_PROP is 0x00000010.
const adsRightDSReadProperty = uint32(0x00000010)

type GMSAMembershipTrustee struct {
	Account string
	Flags   uint8
	Mask    uint32
	SID     string
	Type    string
}

func decodeGMSAMembershipDescriptor(
	encoded []byte,
) ([]GMSAMembershipTrustee, error) {
	if len(encoded) == 0 {
		return nil, fmt.Errorf(
			"security descriptor is empty",
		)
	}

	// SECURITY_DESCRIPTOR contains pointer-sized fields in Go's x/sys/windows
	// representation. Use uintptr-backed storage so checkptr and the native
	// security APIs receive correctly aligned memory even though the LDAP value
	// itself is a self-relative descriptor.
	const pointerSize = int(unsafe.Sizeof(uintptr(0)))
	storage := make(
		[]uintptr,
		(len(encoded)+pointerSize-1)/pointerSize,
	)
	raw := unsafe.Slice(
		(*byte)(unsafe.Pointer(&storage[0])),
		len(encoded),
	)
	copy(raw, encoded)

	descriptor := (*windows.SECURITY_DESCRIPTOR)(
		unsafe.Pointer(&storage[0]),
	)
	if !descriptor.IsValid() {
		runtime.KeepAlive(storage)
		return nil, fmt.Errorf(
			"security descriptor is not valid",
		)
	}

	dacl, _, err := descriptor.DACL()
	if err != nil {
		runtime.KeepAlive(storage)
		return nil, fmt.Errorf(
			"read password-retrieval DACL: %w",
			err,
		)
	}
	if dacl == nil {
		runtime.KeepAlive(storage)
		return nil, fmt.Errorf(
			"password-retrieval security descriptor has a null DACL",
		)
	}

	trustees := make(
		[]GMSAMembershipTrustee,
		0,
		int(dacl.AceCount),
	)

	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(
			dacl,
			uint32(index),
			&ace,
		); err != nil {
			runtime.KeepAlive(storage)
			return nil, fmt.Errorf(
				"read password-retrieval ACE %d: %w",
				index,
				err,
			)
		}
		if ace == nil {
			runtime.KeepAlive(storage)
			return nil, fmt.Errorf(
				"password-retrieval ACE %d is nil",
				index,
			)
		}

		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			runtime.KeepAlive(storage)
			return nil, fmt.Errorf(
				"password-retrieval ACE %d has unsupported type %d; exact simple trustee authorization cannot be proven",
				index,
				ace.Header.AceType,
			)
		}
		if uint32(ace.Mask)&adsRightDSReadProperty == 0 {
			runtime.KeepAlive(storage)
			return nil, fmt.Errorf(
				"password-retrieval ACE %d mask=0x%08X does not include ADS_RIGHT_DS_READ_PROP",
				index,
				uint32(ace.Mask),
			)
		}

		sid := (*windows.SID)(
			unsafe.Pointer(&ace.SidStart),
		)
		if sid == nil || !sid.IsValid() {
			runtime.KeepAlive(storage)
			return nil, fmt.Errorf(
				"password-retrieval ACE %d contains an invalid SID",
				index,
			)
		}

		trustees = append(
			trustees,
			GMSAMembershipTrustee{
				Account: accountNameForSID(sid),
				Flags:   ace.Header.AceFlags,
				Mask:    uint32(ace.Mask),
				SID:     sid.String(),
				Type:    "ALLOW",
			},
		)
	}

	runtime.KeepAlive(storage)

	if len(trustees) == 0 {
		return nil, fmt.Errorf(
			"password-retrieval DACL contains no READ_PROPERTY Allow trustees",
		)
	}

	return trustees, nil
}

func exactSingleGMSATrustee(
	trustees []GMSAMembershipTrustee,
	expectedSID string,
) bool {
	expectedSID = strings.TrimSpace(expectedSID)
	if expectedSID == "" || len(trustees) != 1 {
		return false
	}

	return strings.EqualFold(
		strings.TrimSpace(trustees[0].SID),
		expectedSID,
	)
}

func formatGMSATrustees(
	trustees []GMSAMembershipTrustee,
) string {
	if len(trustees) == 0 {
		return "none"
	}

	values := make([]string, 0, len(trustees))
	for _, trustee := range trustees {
		values = append(
			values,
			fmt.Sprintf(
				"%s/%s/mask=0x%08X",
				valueOrNotKnown(trustee.Account),
				valueOrNotKnown(trustee.SID),
				trustee.Mask,
			),
		)
	}
	return strings.Join(values, ", ")
}

func sidStringFromBinary(
	encoded []byte,
) (string, error) {
	if len(encoded) == 0 {
		return "", fmt.Errorf(
			"SID value is empty",
		)
	}

	const pointerSize = int(unsafe.Sizeof(uintptr(0)))
	storage := make(
		[]uintptr,
		(len(encoded)+pointerSize-1)/pointerSize,
	)
	raw := unsafe.Slice(
		(*byte)(unsafe.Pointer(&storage[0])),
		len(encoded),
	)
	copy(raw, encoded)

	sid := (*windows.SID)(
		unsafe.Pointer(&storage[0]),
	)
	if !sid.IsValid() {
		runtime.KeepAlive(storage)
		return "", fmt.Errorf(
			"SID value is not valid",
		)
	}

	value := sid.String()
	runtime.KeepAlive(storage)

	return value, nil
}
