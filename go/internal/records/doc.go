// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

// Package records defines FI source-record values that keep the same meaning
// when they cross system boundaries.
//
// Windows source systems create these values from collected facts, stage them
// locally, and ship them. Backend components receive and preserve the same
// record meanings.
//
// Windows API structures and collection mechanics do not belong here. Those
// stay under internal/windows. This package contains only the shared record
// representation and validation rules needed at the boundary between systems.
package records
