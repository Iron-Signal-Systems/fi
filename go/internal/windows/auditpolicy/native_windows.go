// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package auditpolicy

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

var (
	advapi32  = syscall.NewLazyDLL("advapi32.dll")
	procQuery = advapi32.NewProc("AuditQuerySystemPolicy")
	procSet   = advapi32.NewProc("AuditSetSystemPolicy")
	procFree  = advapi32.NewProc("AuditFree")
)

type guid struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

type policyInfo struct {
	Subcategory         guid
	AuditingInformation uint32
	Category            guid
}

var (
	_ [36 - unsafe.Sizeof(policyInfo{})]byte
	_ [unsafe.Sizeof(policyInfo{}) - 36]byte
)

var nativeGUIDs = [...]guid{
	{0x0CCE922F, 0x69AE, 0x11D9, [8]byte{0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30}},
	{0x0CCE921D, 0x69AE, 0x11D9, [8]byte{0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30}},
	{0x0CCE9223, 0x69AE, 0x11D9, [8]byte{0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30}},
	{0x0CCE9244, 0x69AE, 0x11D9, [8]byte{0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30}},
}

type Observation struct {
	Subcategory Subcategory
	Flags       uint32
}

func apiError(operation string, callErr error) error {
	if callErr != nil && !errors.Is(callErr, syscall.Errno(0)) {
		return fmt.Errorf("%s: %w", operation, callErr)
	}
	return fmt.Errorf("%s failed", operation)
}

func queryOne(index int) (uint32, error) {
	if index < 0 || index >= len(required) {
		return 0, errors.New("invalid fixed FI audit-policy index")
	}
	g := nativeGUIDs[index]
	var output *policyInfo
	err := withSecurityPrivilege(func() error {
		ok, _, callErr := procQuery.Call(uintptr(unsafe.Pointer(&g)), 1, uintptr(unsafe.Pointer(&output)))
		if ok == 0 {
			return apiError("AuditQuerySystemPolicy", callErr)
		}
		return nil
	})
	if err != nil {
		if output != nil {
			procFree.Call(uintptr(unsafe.Pointer(output)))
		}
		return 0, err
	}
	if output == nil {
		return 0, errors.New("AuditQuerySystemPolicy returned nil policy")
	}
	defer procFree.Call(uintptr(unsafe.Pointer(output)))
	if output.Subcategory != g {
		return 0, fmt.Errorf("AuditQuerySystemPolicy returned wrong subcategory for %s", required[index].ID)
	}
	return output.AuditingInformation, nil
}

func setOne(index int, flags uint32) error {
	if index < 0 || index >= len(required) {
		return errors.New("invalid fixed FI audit-policy index")
	}
	// The API writes a complete subcategory record. Preserve non-FI bits by
	// merging with the precisely discovered old value before calling it.
	v := policyInfo{Subcategory: nativeGUIDs[index], AuditingInformation: flags}
	return withSecurityPrivilege(func() error {
		ok, _, callErr := procSet.Call(uintptr(unsafe.Pointer(&v)), 1)
		if ok == 0 {
			return apiError("AuditSetSystemPolicy", callErr)
		}
		return nil
	})
}

// QueryRequired is for use by the installer and a fixed privileged broker
// operation, never as arbitrary GUID input supplied by Collector.
func QueryRequired() ([]Observation, error) {
	out := make([]Observation, 0, len(required))
	for i, subcategory := range required {
		flags, err := queryOne(i)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", subcategory.ID, err)
		}
		out = append(out, Observation{Subcategory: subcategory, Flags: flags})
	}
	return out, nil
}

// ApplyRequired sets missing bits and hands rollback ownership to Approval 2.
// The installer must capture the registry-precedence setting and governed-root
// SACLs as separate steps of that same transaction before service activation.
// AuditSetSystemPolicy requires the invoking token's policy-write authority.
func ApplyRequired() (func() error, error) {
	old := make([]uint32, len(required))
	desired := make([]uint32, len(required))
	changed := make([]bool, len(required))
	for i, p := range required {
		value, err := queryOne(i)
		if err != nil {
			return nil, fmt.Errorf("snapshot %s: %w", p.ID, err)
		}
		old[i] = value
		desired[i] = Desired(value, p.Required)
	}
	rollback := func() error {
		var failures []error
		for i := len(required) - 1; i >= 0; i-- {
			if !changed[i] {
				continue
			}
			current, err := queryOne(i)
			if err != nil {
				failures = append(failures, fmt.Errorf("rediscover %s: %w", required[i].ID, err))
				continue
			}
			if current != desired[i] {
				failures = append(failures, fmt.Errorf("%s drifted during rollback (expected=%d observed=%d); refusing to overwrite unrelated changes", required[i].ID, desired[i], current))
				continue
			}
			if err := setOne(i, old[i]); err != nil {
				failures = append(failures, fmt.Errorf("restore %s: %w", required[i].ID, err))
			}
		}
		return errors.Join(failures...)
	}
	fail := func(cause error) (func() error, error) {
		return nil, errors.Join(cause, rollback())
	}
	for i, p := range required {
		if desired[i] == old[i] {
			continue
		}
		current, err := queryOne(i)
		if err != nil {
			return fail(fmt.Errorf("rediscover %s before mutation: %w", p.ID, err))
		}
		if current != old[i] {
			return fail(fmt.Errorf("audit-policy drift before mutation for %s: planned=%d observed=%d", p.ID, old[i], current))
		}
		if err := setOne(i, desired[i]); err != nil {
			return fail(fmt.Errorf("enable %s: %w", p.ID, err))
		}
		changed[i] = true
		observed, err := queryOne(i)
		if err != nil {
			return fail(fmt.Errorf("verify %s: %w", p.ID, err))
		}
		if observed != desired[i] {
			return fail(fmt.Errorf("%s did not converge; desired_flags=%d effective_flags=%d", p.ID, desired[i], observed))
		}
	}
	return rollback, nil
}
