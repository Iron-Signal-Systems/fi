// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package auditpolicy

const (
	// These masks are the existing FI audited-root contract; SACL entries
	// audit operations, and must never be confused with a DACL access grant.
	ChangeAccessMask       uint32 = 0x000D0156
	DescendantReadMask     uint32 = 0x00000001
	ChangeACEFlags         uint8  = 0xC3 // ObjectInherit | ContainerInherit | Success | Failure
	DescendantReadACEFlags uint8  = 0xC9 // ObjectInherit | InheritOnly | Success | Failure
)

// selectedEvents exactly mirrors securityevent.SelectEvent and the EvtQuery
// filter on the inspected installer branch. They are selected, not individually
// configurable through auditpol. Some are generated only by specific actions
// (e.g. Security-log clear), which must not be induced during installation.
var selectedEvents = [...]uint32{1102, 4656, 4660, 4663, 4664, 4670, 4719, 4907, 5145}

func SelectedEventIDs() []uint32 {
	out := make([]uint32, len(selectedEvents))
	copy(out, selectedEvents[:])
	return out
}
