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

const policyCreateAccount = uint32(0x00000010)

var (
	lsaAddAccountRightsProc     = advapi32DLL.NewProc("LsaAddAccountRights")
	lsaRemoveAccountRightsProc  = advapi32DLL.NewProc("LsaRemoveAccountRights")
	netLocalGroupAddMembersProc = netapi32DLL.NewProc("NetLocalGroupAddMembers")
	netLocalGroupDelMembersProc = netapi32DLL.NewProc("NetLocalGroupDelMembers")
)

func reconcileServer2016Rights(identities DesiredFIIdentities) (func() error, error) {
	type contract struct {
		account string
		rights  []string
	}
	contracts := []contract{
		{account: identities.CollectorSender.Account, rights: []string{"SeServiceLogonRight"}},
		{account: identities.USNReader.Account, rights: []string{"SeServiceLogonRight"}},
		{account: identities.ObjReader.Account, rights: []string{"SeBackupPrivilege", "SeSecurityPrivilege", "SeServiceLogonRight"}},
	}

	original := make(map[string][]string, len(contracts))
	for _, item := range contracts {
		rights, err := enumerateDirectAccountRights(item.account)
		if err != nil {
			return nil, err
		}
		original[item.account] = append([]string(nil), rights...)
	}

	applied := make([]contract, 0, len(contracts))
	for _, item := range contracts {
		if err := setExactAccountRights(item.account, item.rights); err != nil {
			for index := len(applied) - 1; index >= 0; index-- {
				_ = setExactAccountRights(applied[index].account, original[applied[index].account])
			}
			return nil, err
		}
		applied = append(applied, item)
	}

	return func() error {
		var first error
		for index := len(contracts) - 1; index >= 0; index-- {
			item := contracts[index]
			if err := setExactAccountRights(item.account, original[item.account]); err != nil && first == nil {
				first = err
			}
		}
		return first
	}, nil
}

func setExactAccountRights(account string, desired []string) error {
	current, err := enumerateDirectAccountRights(account)
	if err != nil {
		return err
	}
	current = uniqueSortedFold(current)
	desired = uniqueSortedFold(desired)

	for _, right := range current {
		if containsFold(desired, right) {
			continue
		}
		if err := mutateAccountRight(account, right, false); err != nil {
			return fmt.Errorf("remove %s from %s: %w", right, account, err)
		}
	}
	for _, right := range desired {
		if containsFold(current, right) {
			continue
		}
		if err := mutateAccountRight(account, right, true); err != nil {
			return fmt.Errorf("add %s to %s: %w", right, account, err)
		}
	}

	observed, err := enumerateDirectAccountRights(account)
	if err != nil {
		return err
	}
	if !exactRights(observed, desired) {
		return fmt.Errorf("post-change direct rights for %s are %v; expected %v", account, observed, desired)
	}
	return nil
}

func mutateAccountRight(account string, right string, add bool) error {
	sid, sidBuffer, err := lookupAccountSID(account)
	if err != nil {
		return err
	}

	attributes := lsaObjectAttributes{Length: uint32(unsafe.Sizeof(lsaObjectAttributes{}))}
	var policyHandle uintptr
	status, _, _ := lsaOpenPolicyProc.Call(
		0,
		uintptr(unsafe.Pointer(&attributes)),
		uintptr(policyLookupNames|policyCreateAccount),
		uintptr(unsafe.Pointer(&policyHandle)),
	)
	if status != 0 {
		return lsaStatusError("open local security policy for mutation", status)
	}
	defer lsaCloseProc.Call(policyHandle)

	buffer, err := windows.UTF16FromString(right)
	if err != nil {
		return fmt.Errorf("encode account right %q: %w", right, err)
	}
	if len(buffer) < 2 {
		return fmt.Errorf("account right %q encoded to an empty value", right)
	}
	value := lsaUnicodeString{
		Length:        uint16((len(buffer) - 1) * 2),
		MaximumLength: uint16(len(buffer) * 2),
		Buffer:        &buffer[0],
	}

	if add {
		status, _, _ = lsaAddAccountRightsProc.Call(
			policyHandle,
			uintptr(unsafe.Pointer(sid)),
			uintptr(unsafe.Pointer(&value)),
			1,
		)
	} else {
		status, _, _ = lsaRemoveAccountRightsProc.Call(
			policyHandle,
			uintptr(unsafe.Pointer(sid)),
			0,
			uintptr(unsafe.Pointer(&value)),
			1,
		)
	}

	runtime.KeepAlive(sidBuffer)
	runtime.KeepAlive(buffer)
	if status != 0 {
		op := "remove local account right"
		if add {
			op = "add local account right"
		}
		return lsaStatusError(op, status)
	}
	return nil
}

func reconcileServer2016Groups(identities DesiredFIIdentities) (func() error, error) {
	type contract struct {
		account string
		group   string
		want    bool
	}
	contracts := []contract{
		{account: identities.CollectorSender.Account, group: "Administrators", want: false},
		{account: identities.CollectorSender.Account, group: "Event Log Readers", want: true},
		{account: identities.USNReader.Account, group: "Administrators", want: true},
		{account: identities.ObjReader.Account, group: "Administrators", want: false},
		{account: identities.ObjReader.Account, group: "Backup Operators", want: false},
	}

	original := make([]bool, len(contracts))
	for index, item := range contracts {
		member, err := accountIsDirectLocalGroupMember(item.group, item.account)
		if err != nil {
			return nil, err
		}
		original[index] = member
	}

	applied := 0
	for index, item := range contracts {
		if original[index] != item.want {
			if err := setDirectLocalGroupMembership(item.group, item.account, item.want); err != nil {
				for rollbackIndex := applied - 1; rollbackIndex >= 0; rollbackIndex-- {
					_ = setDirectLocalGroupMembership(contracts[rollbackIndex].group, contracts[rollbackIndex].account, original[rollbackIndex])
				}
				return nil, err
			}
		}
		applied++
	}

	return func() error {
		var first error
		for index := len(contracts) - 1; index >= 0; index-- {
			if err := setDirectLocalGroupMembership(contracts[index].group, contracts[index].account, original[index]); err != nil && first == nil {
				first = err
			}
		}
		return first
	}, nil
}

func setDirectLocalGroupMembership(group string, account string, want bool) error {
	current, err := accountIsDirectLocalGroupMember(group, account)
	if err != nil {
		return err
	}
	if current == want {
		return nil
	}

	groupName, err := syscall.UTF16PtrFromString(group)
	if err != nil {
		return fmt.Errorf("encode local group %q: %w", group, err)
	}
	accountName, err := syscall.UTF16PtrFromString(account)
	if err != nil {
		return fmt.Errorf("encode local account %q: %w", account, err)
	}
	info := localGroupMembersInfo3{DomainAndName: accountName}

	var result uintptr
	if want {
		result, _, _ = netLocalGroupAddMembersProc.Call(
			0,
			uintptr(unsafe.Pointer(groupName)),
			3,
			uintptr(unsafe.Pointer(&info)),
			1,
		)
	} else {
		result, _, _ = netLocalGroupDelMembersProc.Call(
			0,
			uintptr(unsafe.Pointer(groupName)),
			3,
			uintptr(unsafe.Pointer(&info)),
			1,
		)
	}

	runtime.KeepAlive(groupName)
	runtime.KeepAlive(accountName)
	if uint32(result) != 0 {
		op := "remove"
		if want {
			op = "add"
		}
		return fmt.Errorf("%s %s %s local group membership: status=%d", op, account, group, uint32(result))
	}

	observed, err := accountIsDirectLocalGroupMember(group, account)
	if err != nil {
		return err
	}
	if observed != want {
		return fmt.Errorf("post-change local group membership account=%s group=%s observed=%t expected=%t", account, group, observed, want)
	}
	return nil
}

func uniqueSortedFold(values []string) []string {
	seen := make(map[string]string, len(values))
	for _, value := range values {
		key := strings.ToLower(strings.TrimSpace(value))
		if key == "" {
			continue
		}
		if _, ok := seen[key]; !ok {
			seen[key] = value
		}
	}
	result := make([]string, 0, len(seen))
	for _, value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
