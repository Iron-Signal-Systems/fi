// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import "testing"

// The indexed loader authenticates only a selected signed prefix. This test
// prevents broadening that capability beyond legacy bounded windows and
// the precise W128/1GiB isolated continuous-family experiment.
func TestIndexedPrivateWindowLimitsAllowed(t *testing.T) {
    cases := []struct {
        name string
        limits BacklogWindowLimits
        allowed bool
    }{
        {"legacy-W32", BacklogWindowLimits{MaxRecords:32768,MaxDataBytes:256<<20},true},
        {"isolated-W128", BacklogWindowLimits{MaxRecords:131072,MaxDataBytes:1<<30},true},
        {"empty", BacklogWindowLimits{},false},
        {"missing-record-bound", BacklogWindowLimits{MaxDataBytes:1<<30},false},
        {"missing-byte-bound", BacklogWindowLimits{MaxRecords:131072},false},
        {"W128-too-large", BacklogWindowLimits{MaxRecords:131072,MaxDataBytes:(1<<30)+1},false},
        {"unrecognized-1GiB-profile", BacklogWindowLimits{MaxRecords:65536,MaxDataBytes:1<<30},false},
    }
    for _, tc:=range cases {
        t.Run(tc.name,func(t *testing.T) {
            if got:=indexedPrivateWindowLimitsAllowed(tc.limits);got!=tc.allowed{
                t.Fatalf("indexedPrivateWindowLimitsAllowed(%+v)=%v, want %v",tc.limits,got,tc.allowed)
            }
        })
    }
}
