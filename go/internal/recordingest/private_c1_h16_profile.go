//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import "context"

// Exact limits from the original H16 combined-buffer patcher. Retaining
// the complete profile comparison prevents a name-only profile from
// selecting unrelated SQL or buffering behaviour during the C1 port.
func privateH16CombinedFileProfileValid(ctx context.Context) bool {
    got := fileBulkLimitsFromContext(ctx)
    f3 := fileBulkLimits{
        Name:"F3",SourceMaxRecords:8192,SourceMaxBytes:32 << 20,
        ObserveMaxRecords:8192,ObserveMaxBytes:32 << 20,
        HashMaxRows:8192,HashMaxBytes:8 << 20,ChildMaxRows:4096,
    }
    if got == f3 { return true }
    f3.Name = "F3H16"
    f3.HashMaxRows = 16384
    f3.HashMaxBytes = 16 << 20
    return got == f3
}
