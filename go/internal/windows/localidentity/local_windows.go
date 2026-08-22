// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package localidentity

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"runtime"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

const (
	netAPISuccess              = 0
	netAPIErrorMoreData        = 234
	netUserInfoLevel0          = 0
	netUserInfoLevel23         = 23
	netLocalGroupInfoLevel1    = 1
	netLocalGroupMembersLevel2 = 2
	netAPIMaxPreferredLength   = 0xffffffff
	maxLocalUsers              = 65536
	maxLocalGroups             = 65536
	maxLocalMemberships        = 1000000
	maxLocalUTF16Units         = 1 << 20
	maxSIDBytes                = 1024

	ufAccountDisable = 0x0002
	ufLockout        = 0x0010
)

var (
	netapi32                    = syscall.NewLazyDLL("netapi32.dll")
	advapi32                    = syscall.NewLazyDLL("advapi32.dll")
	procNetUserEnum             = netapi32.NewProc("NetUserEnum")
	procNetUserGetInfo          = netapi32.NewProc("NetUserGetInfo")
	procNetLocalGroupEnum       = netapi32.NewProc("NetLocalGroupEnum")
	procNetLocalGroupGetMembers = netapi32.NewProc("NetLocalGroupGetMembers")
	procNetApiBufferFree        = netapi32.NewProc("NetApiBufferFree")
	procLookupAccountNameW      = advapi32.NewProc("LookupAccountNameW")
	procIsValidSid              = advapi32.NewProc("IsValidSid")
	procGetLengthSid            = advapi32.NewProc("GetLengthSid")
)

type userInfo0 struct{ Name *uint16 }

type userInfo23 struct {
	Name     *uint16
	FullName *uint16
	Comment  *uint16
	Flags    uint32
	SID      uintptr
}

type localGroupInfo1 struct {
	Name    *uint16
	Comment *uint16
}

type localGroupMembersInfo2 struct {
	SID           uintptr
	SIDUsage      uint32
	DomainAndName *uint16
}

// CollectLocalPrincipals records local users, local groups, and direct local
// group members from the local Windows security database. It is read-only and
// does not expand nested domain group membership or calculate effective access.
func CollectLocalPrincipals(ctx context.Context, computerName string) (records.LocalPrincipalSnapshot, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return records.LocalPrincipalSnapshot{}, err
	}
	if computerName == "" {
		return records.LocalPrincipalSnapshot{}, fmt.Errorf("computer name is required")
	}

	users, err := collectUsers(ctx)
	if err != nil {
		return records.LocalPrincipalSnapshot{}, err
	}
	groups, memberships, err := collectGroupsAndMemberships(ctx, computerName)
	if err != nil {
		return records.LocalPrincipalSnapshot{}, err
	}

	snapshot := records.LocalPrincipalSnapshot{
		ObservedAt:       time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z"),
		CollectionMethod: records.LocalPrincipalCollectionMethod,
		ComputerName:     computerName,
		Users:            users,
		Groups:           groups,
		Memberships:      memberships,
	}
	records.SortLocalPrincipalSnapshot(&snapshot)
	if err := records.ValidateLocalPrincipalSnapshot(snapshot); err != nil {
		return records.LocalPrincipalSnapshot{}, fmt.Errorf("validate local principal snapshot: %w", err)
	}
	return snapshot, nil
}

func collectUsers(ctx context.Context) ([]records.LocalUserObservation, error) {
	var resume uint32
	users := make([]records.LocalUserObservation, 0)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var buffer uintptr
		var entriesRead, totalEntries uint32
		status, _, _ := procNetUserEnum.Call(
			0, netUserInfoLevel0, 0,
			uintptr(unsafe.Pointer(&buffer)), netAPIMaxPreferredLength,
			uintptr(unsafe.Pointer(&entriesRead)), uintptr(unsafe.Pointer(&totalEntries)),
			uintptr(unsafe.Pointer(&resume)),
		)
		if status != netAPISuccess && status != netAPIErrorMoreData {
			if buffer != 0 {
				procNetApiBufferFree.Call(buffer)
			}
			return nil, fmt.Errorf("NetUserEnum(level 0): status %d", status)
		}
		if int(entriesRead) > maxLocalUsers-len(users) {
			if buffer != 0 {
				procNetApiBufferFree.Call(buffer)
			}
			return nil, fmt.Errorf("local user count exceeds limit %d", maxLocalUsers)
		}
		if entriesRead > 0 && buffer == 0 {
			return nil, fmt.Errorf("NetUserEnum returned entries with nil buffer")
		}
		if entriesRead > 0 {
			items := unsafe.Slice((*userInfo0)(unsafe.Pointer(buffer)), int(entriesRead))
			for _, item := range items {
				name, _, err := utf16PointerValue(item.Name)
				if err != nil || name == "" {
					if buffer != 0 {
						procNetApiBufferFree.Call(buffer)
					}
					return nil, fmt.Errorf("local user name: %w", err)
				}
				user, err := getUser(name)
				if err != nil {
					if buffer != 0 {
						procNetApiBufferFree.Call(buffer)
					}
					return nil, err
				}
				users = append(users, user)
			}
		}
		if buffer != 0 {
			procNetApiBufferFree.Call(buffer)
			buffer = 0
		}
		if status == netAPISuccess {
			break
		}
	}
	return users, nil
}

func getUser(name string) (records.LocalUserObservation, error) {
	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return records.LocalUserObservation{}, err
	}
	var buffer uintptr
	status, _, _ := procNetUserGetInfo.Call(0, uintptr(unsafe.Pointer(namePtr)), netUserInfoLevel23, uintptr(unsafe.Pointer(&buffer)))
	runtime.KeepAlive(namePtr)
	if status != netAPISuccess {
		return records.LocalUserObservation{}, fmt.Errorf("NetUserGetInfo(%q, level 23): status %d", name, status)
	}
	if buffer == 0 {
		return records.LocalUserObservation{}, fmt.Errorf("NetUserGetInfo(%q) returned nil buffer", name)
	}
	defer procNetApiBufferFree.Call(buffer)
	info := (*userInfo23)(unsafe.Pointer(buffer))

	sid, rawSID, err := copySID(info.SID)
	if err != nil {
		return records.LocalUserObservation{}, fmt.Errorf("local user %q SID: %w", name, err)
	}
	nameDisplay, nameRaw, err := utf16PointerValue(info.Name)
	if err != nil || nameDisplay == "" {
		return records.LocalUserObservation{}, fmt.Errorf("local user %q returned invalid name", name)
	}
	fullName, fullNameRaw, err := utf16PointerValue(info.FullName)
	if err != nil {
		return records.LocalUserObservation{}, err
	}
	comment, commentRaw, err := utf16PointerValue(info.Comment)
	if err != nil {
		return records.LocalUserObservation{}, err
	}
	return records.LocalUserObservation{
		SID: sid, SIDRawBase64URL: base64.RawURLEncoding.EncodeToString(rawSID),
		NameDisplay: nameDisplay, NameUTF16LEBase64URL: nameRaw,
		FullNameDisplay: fullName, FullNameUTF16LEBase64URL: fullNameRaw,
		CommentDisplay: comment, CommentUTF16LEBase64URL: commentRaw,
		FlagsRaw:        strconv.FormatUint(uint64(info.Flags), 10),
		AccountDisabled: info.Flags&ufAccountDisable != 0,
		AccountLocked:   info.Flags&ufLockout != 0,
	}, nil
}

func collectGroupsAndMemberships(ctx context.Context, computerName string) ([]records.LocalGroupObservation, []records.LocalGroupMembershipObservation, error) {
	var resume uintptr
	groups := make([]records.LocalGroupObservation, 0)
	memberships := make([]records.LocalGroupMembershipObservation, 0)
	for {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		var buffer uintptr
		var entriesRead, totalEntries uint32
		status, _, _ := procNetLocalGroupEnum.Call(
			0, netLocalGroupInfoLevel1, uintptr(unsafe.Pointer(&buffer)), netAPIMaxPreferredLength,
			uintptr(unsafe.Pointer(&entriesRead)), uintptr(unsafe.Pointer(&totalEntries)), uintptr(unsafe.Pointer(&resume)),
		)
		if status != netAPISuccess && status != netAPIErrorMoreData {
			if buffer != 0 {
				procNetApiBufferFree.Call(buffer)
			}
			return nil, nil, fmt.Errorf("NetLocalGroupEnum(level 1): status %d", status)
		}
		if int(entriesRead) > maxLocalGroups-len(groups) {
			if buffer != 0 {
				procNetApiBufferFree.Call(buffer)
			}
			return nil, nil, fmt.Errorf("local group count exceeds limit %d", maxLocalGroups)
		}
		if entriesRead > 0 && buffer == 0 {
			return nil, nil, fmt.Errorf("NetLocalGroupEnum returned entries with nil buffer")
		}
		if entriesRead > 0 {
			items := unsafe.Slice((*localGroupInfo1)(unsafe.Pointer(buffer)), int(entriesRead))
			for _, item := range items {
				name, nameRaw, err := utf16PointerValue(item.Name)
				if err != nil || name == "" {
					if buffer != 0 {
						procNetApiBufferFree.Call(buffer)
					}
					return nil, nil, fmt.Errorf("local group name invalid")
				}
				comment, commentRaw, err := utf16PointerValue(item.Comment)
				if err != nil {
					if buffer != 0 {
						procNetApiBufferFree.Call(buffer)
					}
					return nil, nil, err
				}
				sid, rawSID, accountDomain, err := lookupLocalGroupSID(computerName, name)
				if err != nil {
					if buffer != 0 {
						procNetApiBufferFree.Call(buffer)
					}
					return nil, nil, err
				}
				group := records.LocalGroupObservation{
					SID: sid, SIDRawBase64URL: base64.RawURLEncoding.EncodeToString(rawSID), AccountDomain: accountDomain,
					NameDisplay: name, NameUTF16LEBase64URL: nameRaw, CommentDisplay: comment, CommentUTF16LEBase64URL: commentRaw,
				}
				edges, state, reason, detail := collectGroupMembers(ctx, name, sid, len(memberships))
				group.MembershipState, group.MembershipReasonCode, group.MembershipDetail = state, reason, detail
				groups = append(groups, group)
				memberships = append(memberships, edges...)
				if len(memberships) > maxLocalMemberships {
					if buffer != 0 {
						procNetApiBufferFree.Call(buffer)
					}
					return nil, nil, fmt.Errorf("local membership count exceeds limit %d", maxLocalMemberships)
				}
			}
		}
		if buffer != 0 {
			procNetApiBufferFree.Call(buffer)
		}
		if status == netAPISuccess {
			break
		}
	}
	return groups, memberships, nil
}

func collectGroupMembers(ctx context.Context, groupName, groupSID string, existingCount int) ([]records.LocalGroupMembershipObservation, string, string, string) {
	var resume uintptr
	edges := make([]records.LocalGroupMembershipObservation, 0)
	for {
		if err := ctx.Err(); err != nil {
			if len(edges) > 0 {
				return edges, records.LocalMembershipPartial, "LocalGroupMembershipReadInterrupted", err.Error()
			}
			return edges, records.LocalMembershipError, "LocalGroupMembershipReadInterrupted", err.Error()
		}
		var buffer uintptr
		var entriesRead, totalEntries uint32
		groupPtr, err := syscall.UTF16PtrFromString(groupName)
		if err != nil {
			return edges, records.LocalMembershipError, "LocalGroupNameInvalid", err.Error()
		}
		status, _, _ := procNetLocalGroupGetMembers.Call(
			0, uintptr(unsafe.Pointer(groupPtr)), netLocalGroupMembersLevel2,
			uintptr(unsafe.Pointer(&buffer)), netAPIMaxPreferredLength,
			uintptr(unsafe.Pointer(&entriesRead)), uintptr(unsafe.Pointer(&totalEntries)), uintptr(unsafe.Pointer(&resume)),
		)
		runtime.KeepAlive(groupPtr)
		if status != netAPISuccess && status != netAPIErrorMoreData {
			if buffer != 0 {
				procNetApiBufferFree.Call(buffer)
			}
			state := records.LocalMembershipError
			if len(edges) > 0 {
				state = records.LocalMembershipPartial
			}
			return edges, state, "LocalGroupMembershipReadFailed", fmt.Sprintf("NetLocalGroupGetMembers(%q): status %d", groupName, status)
		}
		if existingCount+len(edges)+int(entriesRead) > maxLocalMemberships {
			if buffer != 0 {
				procNetApiBufferFree.Call(buffer)
			}
			state := records.LocalMembershipError
			if len(edges) > 0 {
				state = records.LocalMembershipPartial
			}
			return edges, state, "LocalGroupMembershipLimitExceeded", fmt.Sprintf("membership limit %d", maxLocalMemberships)
		}
		if entriesRead > 0 && buffer == 0 {
			return edges, records.LocalMembershipError, "LocalGroupMembershipReadFailed", "entries returned with nil buffer"
		}
		if entriesRead > 0 {
			items := unsafe.Slice((*localGroupMembersInfo2)(unsafe.Pointer(buffer)), int(entriesRead))
			for _, item := range items {
				memberSID, rawSID, err := copySID(item.SID)
				if err != nil {
					if buffer != 0 {
						procNetApiBufferFree.Call(buffer)
					}
					return edges, records.LocalMembershipPartial, "LocalGroupMemberSIDInvalid", err.Error()
				}
				name, nameRaw, err := utf16PointerValue(item.DomainAndName)
				if err != nil {
					if buffer != 0 {
						procNetApiBufferFree.Call(buffer)
					}
					return edges, records.LocalMembershipPartial, "LocalGroupMemberNameInvalid", err.Error()
				}
				edges = append(edges, records.LocalGroupMembershipObservation{
					GroupSID: groupSID, MemberSID: memberSID, MemberSIDRawBase64URL: base64.RawURLEncoding.EncodeToString(rawSID),
					MemberDomainAndNameDisplay: name, MemberDomainAndNameUTF16LEBase64URL: nameRaw,
					SIDNameUseRaw: strconv.FormatUint(uint64(item.SIDUsage), 10), SIDNameUseName: sidNameUseName(item.SIDUsage),
				})
			}
		}
		if buffer != 0 {
			procNetApiBufferFree.Call(buffer)
		}
		if status == netAPISuccess {
			return edges, records.LocalMembershipComplete, "", ""
		}
	}
}

func lookupLocalGroupSID(computerName, groupName string) (string, []byte, string, error) {
	candidates := []string{computerName + "\\" + groupName, "BUILTIN\\" + groupName, groupName}
	var lastErr error
	for _, candidate := range candidates {
		sid, raw, domain, err := lookupAccount(candidate)
		if err == nil {
			return sid, raw, domain, nil
		}
		lastErr = err
	}
	return "", nil, "", fmt.Errorf("resolve local group %q SID: %w", groupName, lastErr)
}

func lookupAccount(account string) (string, []byte, string, error) {
	accountPtr, err := syscall.UTF16PtrFromString(account)
	if err != nil {
		return "", nil, "", err
	}
	var sidSize, domainSize uint32
	var use uint32
	procLookupAccountNameW.Call(0, uintptr(unsafe.Pointer(accountPtr)), 0, uintptr(unsafe.Pointer(&sidSize)), 0, uintptr(unsafe.Pointer(&domainSize)), uintptr(unsafe.Pointer(&use)))
	runtime.KeepAlive(accountPtr)
	if sidSize == 0 || sidSize > maxSIDBytes {
		return "", nil, "", fmt.Errorf("LookupAccountNameW(%q) did not return a bounded SID size", account)
	}
	sidBuffer := make([]byte, sidSize)
	domainBuffer := make([]uint16, domainSize)
	var domainPtr uintptr
	if len(domainBuffer) > 0 {
		domainPtr = uintptr(unsafe.Pointer(&domainBuffer[0]))
	}
	result, _, callErr := procLookupAccountNameW.Call(
		0, uintptr(unsafe.Pointer(accountPtr)), uintptr(unsafe.Pointer(&sidBuffer[0])), uintptr(unsafe.Pointer(&sidSize)),
		domainPtr, uintptr(unsafe.Pointer(&domainSize)), uintptr(unsafe.Pointer(&use)),
	)
	runtime.KeepAlive(accountPtr)
	runtime.KeepAlive(domainBuffer)
	if result == 0 {
		return "", nil, "", fmt.Errorf("LookupAccountNameW(%q): %w", account, callErr)
	}
	sid, err := sidBytesToString(sidBuffer[:sidSize])
	if err != nil {
		return "", nil, "", err
	}
	domain := ""
	if domainSize > 0 && len(domainBuffer) > 0 {
		limit := int(domainSize)
		if limit > len(domainBuffer) {
			limit = len(domainBuffer)
		}
		domain = syscall.UTF16ToString(domainBuffer[:limit])
	}
	return sid, append([]byte(nil), sidBuffer[:sidSize]...), domain, nil
}

func copySID(ptr uintptr) (string, []byte, error) {
	if ptr == 0 {
		return "", nil, fmt.Errorf("nil SID")
	}
	valid, _, _ := procIsValidSid.Call(ptr)
	if valid == 0 {
		return "", nil, fmt.Errorf("invalid SID")
	}
	length, _, _ := procGetLengthSid.Call(ptr)
	if length == 0 || length > maxSIDBytes {
		return "", nil, fmt.Errorf("SID length %d outside bounds", length)
	}
	raw := make([]byte, int(length))
	copy(raw, unsafe.Slice((*byte)(unsafe.Pointer(ptr)), int(length)))
	sid, err := sidBytesToString(raw)
	if err != nil {
		return "", nil, err
	}
	return sid, raw, nil
}

func sidBytesToString(raw []byte) (string, error) {
	if len(raw) < 8 {
		return "", fmt.Errorf("SID too short")
	}
	count := int(raw[1])
	expected := 8 + count*4
	if count > 15 || len(raw) != expected {
		return "", fmt.Errorf("SID length mismatch")
	}
	authority := uint64(0)
	for _, b := range raw[2:8] {
		authority = authority<<8 | uint64(b)
	}
	value := fmt.Sprintf("S-%d-%d", raw[0], authority)
	for i := 0; i < count; i++ {
		value += fmt.Sprintf("-%d", binary.LittleEndian.Uint32(raw[8+i*4:12+i*4]))
	}
	return value, nil
}

func utf16PointerValue(ptr *uint16) (string, string, error) {
	if ptr == nil {
		return "", "", nil
	}
	units := unsafe.Slice(ptr, maxLocalUTF16Units)
	for i, unit := range units {
		if unit == 0 {
			raw := make([]byte, i*2)
			for j, u := range units[:i] {
				binary.LittleEndian.PutUint16(raw[j*2:], u)
			}
			return syscall.UTF16ToString(units[:i]), base64.RawURLEncoding.EncodeToString(raw), nil
		}
	}
	return "", "", fmt.Errorf("unterminated UTF-16 string exceeds %d code units", maxLocalUTF16Units)
}

func sidNameUseName(value uint32) string {
	switch value {
	case 1:
		return "User"
	case 2:
		return "Group"
	case 3:
		return "Domain"
	case 4:
		return "Alias"
	case 5:
		return "WellKnownGroup"
	case 6:
		return "DeletedAccount"
	case 7:
		return "Invalid"
	case 8:
		return "Unknown"
	case 9:
		return "Computer"
	case 10:
		return "Label"
	case 11:
		return "LogonSession"
	default:
		return "NotKnown"
	}
}
