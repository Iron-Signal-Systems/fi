// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

// Package auditpolicy owns the bounded Windows audit-policy prerequisite
// contract. It deliberately does not grant Collector configuration privileges.
package auditpolicy

const (
	Success uint32 = 0x1
	Failure uint32 = 0x2
)

// Subcategory is a fixed FI-owned audit-policy requirement. Neither callers
// nor the Collector can supply an arbitrary category to the privileged broker.
type Subcategory struct {
	ID       string
	GUID     string
	Required uint32
}

var required = [...]Subcategory{
	{ID: "Audit Policy Change", GUID: "{0CCE922F-69AE-11D9-BED3-505054503030}", Required: Success},
	{ID: "File System", GUID: "{0CCE921D-69AE-11D9-BED3-505054503030}", Required: Success | Failure},
	{ID: "Handle Manipulation", GUID: "{0CCE9223-69AE-11D9-BED3-505054503030}", Required: Failure},
	{ID: "Detailed File Share", GUID: "{0CCE9244-69AE-11D9-BED3-505054503030}", Required: Success | Failure},
}

// Required returns a copy, never a mutable view of the audited policy set.
func Required() []Subcategory {
	out := make([]Subcategory, len(required))
	copy(out, required[:])
	return out
}

// Desired preserves unrelated existing audit bits and adds only the missing
// Success/Failure prerequisites. No auditing bit is disabled by an FI install.
func Desired(current, required uint32) uint32 {
	return current | required
}

// Sufficient reports whether all mandatory bits remain effective.
func Sufficient(current, required uint32) bool {
	return current&required == required
}
