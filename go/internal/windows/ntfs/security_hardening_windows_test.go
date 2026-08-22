// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package ntfs

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"unsafe"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

const (
	writeDAC                   = 0x00040000
	seFileObject               = 1
	protectedDACLInformation   = 0x80000000
	objectInheritACE           = 0x01
	inheritOnlyACE             = 0x08
	inheritedACE               = 0x10
	unprotectedDACLInformation = 0x20000000
	fileReadDataMask           = 0x00000001
	fileWriteDataMask          = 0x00000002
	readControlMask            = 0x00020000
	fileAllAccessMask          = 0x001F01FF
)

var procSetSecurityInfoForTest = securityAdvapi32.NewProc("SetSecurityInfo")

func TestSecurityNativeDenyACE(t *testing.T) {
	handle, cleanup := createSecurityTestFile(t)
	defer cleanup()

	everyone := nativeTestSID(1, 0)
	deny := nativeTestSimpleACE(0x01, 0, fileWriteDataMask, everyone)
	allow := nativeTestSimpleACE(0x00, 0, readControlMask|fileReadDataMask, everyone)

	if err := setNativeTestDACL(handle, nativeTestACL(deny, allow)); err != nil {
		t.Fatal(err)
	}

	// Query through the handle opened before the DACL change. This test is about
	// preserving the native deny ACE, its order, mask, SID, and raw bytes; it is
	// not a second test of ReOpenFile authorization.
	observation := queryAndParseSecurityFromOpenHandle(t, handle)
	if observation.DACL.State != records.ACLStatePresent || len(observation.DACL.ACEs) != 2 {
		t.Fatalf("DACL = %#v", observation.DACL)
	}

	denyACE := observation.DACL.ACEs[0]
	if denyACE.TypeName != "AccessDenied" || denyACE.Mask != "2" || denyACE.SID != "S-1-1-0" {
		t.Fatalf("deny ACE = %#v", denyACE)
	}
	if denyACE.RawBase64URL == "" {
		t.Fatal("deny ACE raw bytes were not preserved")
	}

	allowACE := observation.DACL.ACEs[1]
	if allowACE.TypeName != "AccessAllowed" || allowACE.Mask != "131073" || allowACE.SID != "S-1-1-0" {
		t.Fatalf("allow ACE = %#v", allowACE)
	}
}

func TestSecurityNativeInheritedACE(t *testing.T) {
	parentHandle, directory, cleanup := createSecurityInheritanceParent(t)
	defer cleanup()

	everyone := nativeTestSID(1, 0)

	// Keep the parent usable for child creation with one explicit parent-only ACE.
	parentAllow := nativeTestSimpleACE(0x00, 0, fileAllAccessMask, everyone)
	// This ACE is not effective on the parent. It exists only to be inherited by
	// file children. Windows must set INHERITED_ACE on the child's copy.
	inheritable := nativeTestSimpleACE(0x00, objectInheritACE|inheritOnlyACE, fileAllAccessMask, everyone)
	if err := setNativeTestDACL(parentHandle, nativeTestACL(parentAllow, inheritable)); err != nil {
		t.Fatal(err)
	}

	childPath := filepath.Join(directory, "child.txt")
	if err := os.WriteFile(childPath, []byte("fi"), 0o600); err != nil {
		t.Fatal(err)
	}

	childUnits, err := syscall.UTF16FromString(childPath)
	if err != nil {
		t.Fatal(err)
	}
	childHandle, err := syscall.CreateFile(
		&childUnits[0],
		readControl|writeDAC,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = setNativeTestDACL(childHandle, nil)
		_ = syscall.CloseHandle(childHandle)
	}()

	observation := queryAndParseSecurityFromOpenHandle(t, childHandle)
	if observation.DACL.State != records.ACLStatePresent {
		t.Fatalf("DACL state = %q", observation.DACL.State)
	}

	found := false
	for _, ace := range observation.DACL.ACEs {
		flags, err := strconv.ParseUint(ace.Flags, 10, 8)
		if err != nil {
			t.Fatalf("ACE flags %q: %v", ace.Flags, err)
		}
		if ace.TypeName == "AccessAllowed" &&
			ace.Mask == "2032127" &&
			ace.SID == "S-1-1-0" &&
			byte(flags)&inheritedACE != 0 {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("no Windows-inherited ACE found in %#v", observation.DACL.ACEs)
	}
}

func TestSecurityNativeEmptyDACL(t *testing.T) {
	handle, cleanup := createSecurityTestFile(t)
	defer cleanup()

	if err := setNativeTestDACL(handle, nativeTestACL()); err != nil {
		t.Fatal(err)
	}

	// An empty DACL denies all new access. Query the descriptor through the
	// already-open test handle, whose READ_CONTROL access was granted before the
	// empty DACL was installed. Reopening with READ_CONTROL is intentionally not
	// required for this semantic test.
	observation := queryAndParseSecurityFromOpenHandle(t, handle)
	if observation.DACL.State != records.ACLStatePresent {
		t.Fatalf("DACL state = %q", observation.DACL.State)
	}
	if observation.DACL.Size != "8" || len(observation.DACL.ACEs) != 0 {
		t.Fatalf("empty DACL = %#v", observation.DACL)
	}
}

func TestSecurityNativeNullDACL(t *testing.T) {
	handle, cleanup := createSecurityTestFile(t)
	defer cleanup()

	if err := setNativeTestDACL(handle, nil); err != nil {
		t.Fatal(err)
	}
	observation := queryAndParseSecurity(t, handle)
	if observation.DACL.State != records.ACLStateNull {
		t.Fatalf("DACL state = %q", observation.DACL.State)
	}
	if observation.DACL.Revision != "" || observation.DACL.Size != "" || len(observation.DACL.ACEs) != 0 {
		t.Fatalf("NULL DACL contains ACL fields: %#v", observation.DACL)
	}
}

func queryAndParseSecurity(t *testing.T, handle syscall.Handle) records.SecurityObservation {
	t.Helper()
	raw, err := querySecurityDescriptor(handle)
	if err != nil {
		t.Fatal(err)
	}
	return parseAndValidateSecurity(t, raw)
}

func queryAndParseSecurityFromOpenHandle(t *testing.T, handle syscall.Handle) records.SecurityObservation {
	t.Helper()
	raw, err := querySecurityDescriptorFromOpenHandle(handle)
	if err != nil {
		t.Fatal(err)
	}
	return parseAndValidateSecurity(t, raw)
}

func parseAndValidateSecurity(t *testing.T, raw []byte) records.SecurityObservation {
	t.Helper()
	observation, err := records.ParseSecurityDescriptor(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := records.ValidateSecurityObservation(observation); err != nil {
		t.Fatal(err)
	}
	return observation
}

// querySecurityDescriptorFromOpenHandle is test-only. It uses the rights that
// were granted when createSecurityTestFile opened the handle, allowing the test
// to inspect an empty DACL after that DACL prevents all new opens.
func querySecurityDescriptorFromOpenHandle(handle syscall.Handle) ([]byte, error) {
	requested := uintptr(ownerSecurityInformation | groupSecurityInformation | daclSecurityInformation)
	var needed uint32
	result, _, callErr := procGetKernelObjectSecurity.Call(
		uintptr(handle),
		requested,
		0,
		0,
		uintptr(unsafe.Pointer(&needed)),
	)
	if result != 0 && needed == 0 {
		return nil, syscall.EINVAL
	}
	if needed == 0 {
		return nil, windowsCallError("GetKernelObjectSecurity(size)", callErr)
	}
	if needed > maximumSecurityDescriptorBuffer {
		return nil, syscall.ENOMEM
	}

	buffer := make([]byte, needed)
	result, _, callErr = procGetKernelObjectSecurity.Call(
		uintptr(handle),
		requested,
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
		uintptr(unsafe.Pointer(&needed)),
	)
	if result == 0 {
		return nil, windowsCallError("GetKernelObjectSecurity", callErr)
	}
	if needed == 0 || int(needed) > len(buffer) {
		return nil, syscall.EINVAL
	}
	return append([]byte(nil), buffer[:needed]...), nil
}

func createSecurityInheritanceParent(t *testing.T) (syscall.Handle, string, func()) {
	t.Helper()

	directory, err := os.MkdirTemp("", "fi-security-inheritance-*")
	if err != nil {
		t.Fatal(err)
	}

	parentUnits, err := syscall.UTF16FromString(directory)
	if err != nil {
		os.RemoveAll(directory)
		t.Fatal(err)
	}
	parentHandle, err := syscall.CreateFile(
		&parentUnits[0],
		readControl|writeDAC,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		os.RemoveAll(directory)
		t.Fatal(err)
	}

	cleanup := func() {
		// Restore a NULL DACL through the original handle so cleanup does not depend
		// on whatever ACL shape the test installed.
		_ = setNativeTestDACL(parentHandle, nil)
		_ = syscall.CloseHandle(parentHandle)
		_ = os.RemoveAll(directory)
	}
	return parentHandle, directory, cleanup
}

func createSecurityTestFile(t *testing.T) (syscall.Handle, func()) {
	t.Helper()
	file, err := os.CreateTemp("", "fi-security-hardening-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	path := file.Name()
	if err := file.Close(); err != nil {
		os.Remove(path)
		t.Fatal(err)
	}

	units, err := syscall.UTF16FromString(path)
	if err != nil {
		os.Remove(path)
		t.Fatal(err)
	}
	handle, err := syscall.CreateFile(
		&units[0],
		readControl|writeDAC,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		os.Remove(path)
		t.Fatal(err)
	}

	cleanup := func() {
		// A NULL DACL restores unrestricted DACL access before cleanup even when
		// the test deliberately installed an empty/denying DACL.
		_ = setNativeTestDACL(handle, nil)
		_ = syscall.CloseHandle(handle)
		_ = os.Remove(path)
	}
	return handle, cleanup
}

func setNativeTestDACL(handle syscall.Handle, acl []byte) error {
	return setNativeTestDACLWithInformation(
		handle,
		acl,
		daclSecurityInformation|protectedDACLInformation,
	)
}

func setNativeTestDACLWithInformation(handle syscall.Handle, acl []byte, information uint32) error {
	var aclPointer uintptr
	if len(acl) != 0 {
		aclPointer = uintptr(unsafe.Pointer(&acl[0]))
	}
	result, _, _ := procSetSecurityInfoForTest.Call(
		uintptr(handle),
		seFileObject,
		uintptr(information),
		0,
		0,
		aclPointer,
		0,
	)
	runtime.KeepAlive(acl)
	if result != 0 {
		return syscall.Errno(result)
	}
	return nil
}

func nativeTestACL(aces ...[]byte) []byte {
	size := 8
	for _, ace := range aces {
		size += len(ace)
	}
	acl := make([]byte, size)
	acl[0] = 2
	binary.LittleEndian.PutUint16(acl[2:4], uint16(size))
	binary.LittleEndian.PutUint16(acl[4:6], uint16(len(aces)))
	cursor := 8
	for _, ace := range aces {
		copy(acl[cursor:], ace)
		cursor += len(ace)
	}
	return acl
}

func nativeTestSimpleACE(aceType byte, flags byte, mask uint32, sid []byte) []byte {
	ace := make([]byte, 8+len(sid))
	ace[0] = aceType
	ace[1] = flags
	binary.LittleEndian.PutUint16(ace[2:4], uint16(len(ace)))
	binary.LittleEndian.PutUint32(ace[4:8], mask)
	copy(ace[8:], sid)
	return ace
}

func nativeTestSID(authority uint64, subAuthorities ...uint32) []byte {
	sid := make([]byte, 8+len(subAuthorities)*4)
	sid[0] = 1
	sid[1] = byte(len(subAuthorities))
	for index := 0; index < 6; index++ {
		shift := uint((5 - index) * 8)
		sid[2+index] = byte(authority >> shift)
	}
	for index, subAuthority := range subAuthorities {
		start := 8 + index*4
		binary.LittleEndian.PutUint32(sid[start:start+4], subAuthority)
	}
	return sid
}
