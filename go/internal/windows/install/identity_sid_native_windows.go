// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"fmt"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	netErrorMemberInAlias    = uint32(1378)
	netErrorMemberNotInAlias = uint32(1377)
)

type localGroupMembersInfo0 struct {
	SID *windows.SID
}

func accountSIDIsDirectLocalGroupMember(
	group string,
	sid *windows.SID,
) (bool, error) {
	if sid == nil {
		return false, fmt.Errorf(
			"local-group membership SID is unavailable for group %s",
			group,
		)
	}

	resolvedGroup, err := resolveLocalGroupName(
		group,
	)
	if err != nil {
		return false, err
	}

	groupName, err := syscall.UTF16PtrFromString(
		resolvedGroup,
	)
	if err != nil {
		return false, fmt.Errorf(
			"encode local group %q resolved as %q: %w",
			group,
			resolvedGroup,
			err,
		)
	}

	expectedSID := strings.ToUpper(
		strings.TrimSpace(
			sid.String(),
		),
	)

	var resume uintptr

	for {
		var buffer uintptr
		var entriesRead uint32
		var totalEntries uint32

		status, _, _ := netLocalGroupGetMembersProc.Call(
			0,
			uintptr(unsafe.Pointer(groupName)),
			0,
			uintptr(unsafe.Pointer(&buffer)),
			uintptr(maxPreferredSize),
			uintptr(unsafe.Pointer(&entriesRead)),
			uintptr(unsafe.Pointer(&totalEntries)),
			uintptr(unsafe.Pointer(&resume)),
		)

		if buffer != 0 {
			entrySize := unsafe.Sizeof(
				localGroupMembersInfo0{},
			)

			for index := uint32(0); index < entriesRead; index++ {
				entry := (*localGroupMembersInfo0)(
					unsafe.Pointer(
						buffer +
							uintptr(index)*entrySize,
					),
				)

				if entry.SID == nil {
					continue
				}

				observedSID := strings.ToUpper(
					strings.TrimSpace(
						entry.SID.String(),
					),
				)

				if observedSID == expectedSID {
					_, _, _ =
						netApiBufferFreeProc.Call(
							buffer,
						)

					return true, nil
				}
			}

			_, _, _ =
				netApiBufferFreeProc.Call(
					buffer,
				)
		}

		switch syscall.Errno(status) {
		case 0:
			return false, nil

		case errorMoreData:
			continue

		default:
			return false, fmt.Errorf(
				"enumerate local group %q SID members: status=%d",
				group,
				status,
			)
		}
	}
}

func authoritativeDesiredFIIdentitySID(
	identity DesiredFIIdentity,
) (*windows.SID, error) {
	sealed, err :=
		sealedDesiredFIIdentitySID(
			identity,
		)
	if err != nil {
		return nil, err
	}

	current, currentBuffer, err :=
		lookupAccountSID(
			identity.Account,
		)
	if err != nil {
		return nil, fmt.Errorf(
			"revalidate sealed SID for %s: %w",
			identity.Account,
			err,
		)
	}

	currentValue := strings.ToUpper(
		strings.TrimSpace(
			current.String(),
		),
	)
	sealedValue := strings.ToUpper(
		strings.TrimSpace(
			sealed.String(),
		),
	)

	runtime.KeepAlive(
		currentBuffer,
	)

	if currentValue != sealedValue {
		return nil, fmt.Errorf(
			"security identity changed after approval: account=%s sealed_sid=%s current_sid=%s",
			identity.Account,
			sealedValue,
			currentValue,
		)
	}

	return sealed, nil
}

func bindDesiredFIIdentitySIDs(
	report Report,
	identities DesiredFIIdentities,
) (DesiredFIIdentities, error) {
	for _, identity := range []*DesiredFIIdentity{
		&identities.CollectorSender,
		&identities.CRLRefresher,
		&identities.USNReader,
		&identities.ObjReader,
	} {
		state, found :=
			findADGMSA(
				report.AD.GMSAs,
				identity.SAMAccountName,
			)

		if !found {
			continue
		}

		value := strings.ToUpper(
			strings.TrimSpace(
				state.SID,
			),
		)

		if value == "" {
			if report.AD.GMSADiscoveryKnown {
				return DesiredFIIdentities{}, fmt.Errorf(
					"authoritative AD gMSA objectSid is unavailable for %s",
					identity.Account,
				)
			}

			continue
		}

		if _, err :=
			windows.StringToSid(
				value,
			); err != nil {
			return DesiredFIIdentities{}, fmt.Errorf(
				"authoritative AD gMSA objectSid for %s is invalid: %q: %w",
				identity.Account,
				value,
				err,
			)
		}

		identity.SID = value
	}

	return identities, nil
}

func desiredFIIdentityByAccount(
	identities DesiredFIIdentities,
	account string,
) (DesiredFIIdentity, bool) {
	account = strings.TrimSpace(
		account,
	)

	for _, identity := range desiredFIIdentityList(
		identities,
	) {
		if strings.EqualFold(
			strings.TrimSpace(
				identity.Account,
			),
			account,
		) {
			return identity, true
		}
	}

	return DesiredFIIdentity{}, false
}

func enumerateDirectAccountRightsSID(
	sid *windows.SID,
	account string,
) ([]string, error) {
	if sid == nil {
		return nil, fmt.Errorf(
			"direct-right SID is unavailable for %s",
			account,
		)
	}

	attributes := lsaObjectAttributes{
		Length: uint32(
			unsafe.Sizeof(
				lsaObjectAttributes{},
			),
		),
	}

	var policyHandle uintptr

	status, _, _ := lsaOpenPolicyProc.Call(
		0,
		uintptr(
			unsafe.Pointer(
				&attributes,
			),
		),
		uintptr(policyLookupNames),
		uintptr(
			unsafe.Pointer(
				&policyHandle,
			),
		),
	)
	if status != 0 {
		return nil, lsaStatusError(
			"open local security policy",
			status,
		)
	}
	defer lsaCloseProc.Call(
		policyHandle,
	)

	var rightsPointer uintptr
	var rightsCount uint32

	status, _, _ =
		lsaEnumerateAccountRightsProc.Call(
			policyHandle,
			uintptr(
				unsafe.Pointer(
					sid,
				),
			),
			uintptr(
				unsafe.Pointer(
					&rightsPointer,
				),
			),
			uintptr(
				unsafe.Pointer(
					&rightsCount,
				),
			),
		)

	if uint32(status) ==
		statusObjectNameNotFound {
		return []string{}, nil
	}

	if status != 0 {
		return nil, lsaStatusError(
			"enumerate direct account rights for "+account,
			status,
		)
	}

	if rightsPointer == 0 ||
		rightsCount == 0 {
		return []string{}, nil
	}

	defer lsaFreeMemoryProc.Call(
		rightsPointer,
	)

	values := unsafe.Slice(
		(*lsaUnicodeString)(
			unsafe.Pointer(
				rightsPointer,
			),
		),
		int(rightsCount),
	)

	rights := make(
		[]string,
		0,
		rightsCount,
	)

	for _, value := range values {
		if value.Buffer == nil ||
			value.Length == 0 {
			continue
		}

		characters := unsafe.Slice(
			value.Buffer,
			int(value.Length/2),
		)

		right := windows.UTF16ToString(
			characters,
		)

		if strings.TrimSpace(
			right,
		) != "" {
			rights = append(
				rights,
				right,
			)
		}
	}

	sort.Strings(
		rights,
	)

	return rights, nil
}

func mutateAccountRightSID(
	sid *windows.SID,
	account string,
	right string,
	add bool,
) error {
	if sid == nil {
		return fmt.Errorf(
			"direct-right SID is unavailable for %s",
			account,
		)
	}

	attributes := lsaObjectAttributes{
		Length: uint32(
			unsafe.Sizeof(
				lsaObjectAttributes{},
			),
		),
	}

	var policyHandle uintptr

	status, _, _ := lsaOpenPolicyProc.Call(
		0,
		uintptr(
			unsafe.Pointer(
				&attributes,
			),
		),
		uintptr(
			policyLookupNames|
				policyCreateAccount,
		),
		uintptr(
			unsafe.Pointer(
				&policyHandle,
			),
		),
	)
	if status != 0 {
		return lsaStatusError(
			"open local security policy for mutation",
			status,
		)
	}
	defer lsaCloseProc.Call(
		policyHandle,
	)

	buffer, err := windows.UTF16FromString(
		right,
	)
	if err != nil {
		return fmt.Errorf(
			"encode account right %q: %w",
			right,
			err,
		)
	}

	if len(buffer) < 2 {
		return fmt.Errorf(
			"account right %q encoded to an empty value",
			right,
		)
	}

	value := lsaUnicodeString{
		Length: uint16(
			(len(buffer) - 1) * 2,
		),
		MaximumLength: uint16(
			len(buffer) * 2,
		),
		Buffer: &buffer[0],
	}

	if add {
		status, _, _ =
			lsaAddAccountRightsProc.Call(
				policyHandle,
				uintptr(
					unsafe.Pointer(
						sid,
					),
				),
				uintptr(
					unsafe.Pointer(
						&value,
					),
				),
				1,
			)
	} else {
		status, _, _ =
			lsaRemoveAccountRightsProc.Call(
				policyHandle,
				uintptr(
					unsafe.Pointer(
						sid,
					),
				),
				0,
				uintptr(
					unsafe.Pointer(
						&value,
					),
				),
				1,
			)
	}

	runtime.KeepAlive(
		buffer,
	)

	if status != 0 {
		op := "remove local account right"
		if add {
			op = "add local account right"
		}

		return lsaStatusError(
			op,
			status,
		)
	}

	return nil
}

func sealedDesiredFIIdentitySID(
	identity DesiredFIIdentity,
) (*windows.SID, error) {
	value := strings.ToUpper(
		strings.TrimSpace(
			identity.SID,
		),
	)

	if value == "" {
		return nil, fmt.Errorf(
			"sealed SID is unavailable for %s",
			identity.Account,
		)
	}

	sid, err := windows.StringToSid(
		value,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"parse sealed SID for %s: %q: %w",
			identity.Account,
			value,
			err,
		)
	}

	return sid, nil
}

func setDirectLocalGroupMembershipSID(
	group string,
	account string,
	sid *windows.SID,
	want bool,
) error {
	current, err :=
		accountSIDIsDirectLocalGroupMember(
			group,
			sid,
		)
	if err != nil {
		return err
	}

	if current == want {
		return nil
	}

	resolvedGroup, err := resolveLocalGroupName(
		group,
	)
	if err != nil {
		return err
	}

	groupName, err := syscall.UTF16PtrFromString(
		resolvedGroup,
	)
	if err != nil {
		return fmt.Errorf(
			"encode local group %q resolved as %q: %w",
			group,
			resolvedGroup,
			err,
		)
	}

	info := localGroupMembersInfo0{
		SID: sid,
	}

	var result uintptr

	if want {
		result, _, _ =
			netLocalGroupAddMembersProc.Call(
				0,
				uintptr(
					unsafe.Pointer(
						groupName,
					),
				),
				0,
				uintptr(
					unsafe.Pointer(
						&info,
					),
				),
				1,
			)
	} else {
		result, _, _ =
			netLocalGroupDelMembersProc.Call(
				0,
				uintptr(
					unsafe.Pointer(
						groupName,
					),
				),
				0,
				uintptr(
					unsafe.Pointer(
						&info,
					),
				),
				1,
			)
	}

	runtime.KeepAlive(
		groupName,
	)
	runtime.KeepAlive(
		sid,
	)

	status :=
		uint32(result)

	allowedIdempotent :=
		(want &&
			status == netErrorMemberInAlias) ||
			(!want &&
				status == netErrorMemberNotInAlias)

	if status != 0 &&
		!allowedIdempotent {
		op := "remove"
		if want {
			op = "add"
		}

		return fmt.Errorf(
			"%s SID %s (%s) %s local group membership: status=%d",
			op,
			sid.String(),
			account,
			group,
			status,
		)
	}

	observed, err :=
		accountSIDIsDirectLocalGroupMember(
			group,
			sid,
		)
	if err != nil {
		return err
	}

	if observed != want {
		return fmt.Errorf(
			"post-change local group membership account=%s sid=%s group=%s observed=%t expected=%t status=%d",
			account,
			sid.String(),
			group,
			observed,
			want,
			status,
		)
	}

	return nil
}

func setExactAccountRightsSID(
	sid *windows.SID,
	account string,
	desired []string,
) error {
	current, err :=
		enumerateDirectAccountRightsSID(
			sid,
			account,
		)
	if err != nil {
		return err
	}

	current =
		uniqueSortedFold(
			current,
		)
	desired =
		uniqueSortedFold(
			desired,
		)

	for _, right := range current {
		if containsFold(
			desired,
			right,
		) {
			continue
		}

		if err :=
			mutateAccountRightSID(
				sid,
				account,
				right,
				false,
			); err != nil {
			return fmt.Errorf(
				"remove %s from %s: %w",
				right,
				account,
				err,
			)
		}
	}

	for _, right := range desired {
		if containsFold(
			current,
			right,
		) {
			continue
		}

		if err :=
			mutateAccountRightSID(
				sid,
				account,
				right,
				true,
			); err != nil {
			return fmt.Errorf(
				"add %s to %s: %w",
				right,
				account,
				err,
			)
		}
	}

	observed, err :=
		enumerateDirectAccountRightsSID(
			sid,
			account,
		)
	if err != nil {
		return err
	}

	if !exactRights(
		observed,
		desired,
	) {
		return fmt.Errorf(
			"post-change direct rights for %s sid=%s are %v; expected %v",
			account,
			sid.String(),
			observed,
			desired,
		)
	}

	return nil
}
