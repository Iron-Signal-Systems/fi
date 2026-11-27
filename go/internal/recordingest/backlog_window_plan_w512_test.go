// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
    "reflect"
    "testing"
)

// TestBacklogWindowsW512TwoGiBRecordBound proves that W512 changes only
// the immutable signed-window grouping: source batches remain whole, the
// selected record cap is exact, and original receipt metadata is unchanged.
func TestBacklogWindowsW512TwoGiBRecordBound(t *testing.T) {
    sizes := make([]int, 65)
    for i := range sizes {
        sizes[i] = 8192
    }
    g := backlogWindowFixture(sizes, 16<<20)
    receipt := g.Receipt
    batches := append([]PreparedBatch(nil), g.Batches...)
    limits := BacklogWindowLimits{MaxRecords: 524288, MaxDataBytes: 2 << 30}

    got, err := PlanBacklogWindows(g, limits)
    if err != nil {
        t.Fatal(err)
    }
    want := []BacklogWindow{
        {StartBatch: 0, EndBatch: 64, StartRecord: 0, EndRecord: 524288, DataBytes: 1 << 30},
        {StartBatch: 64, EndBatch: 65, StartRecord: 524288, EndRecord: 532480, DataBytes: 16 << 20},
    }
    if !reflect.DeepEqual(got, want) {
        t.Fatalf("W512 record-budget grouping: got=%+v want=%+v", got, want)
    }
    if !reflect.DeepEqual(receipt, g.Receipt) || !reflect.DeepEqual(batches, g.Batches) {
        t.Fatal("W512 grouping mutated the signed batch/receipt evidence")
    }
}

// TestBacklogWindowsW512TwoGiBByteBound verifies that the byte ceiling can
// close a window before 524288 records without splitting an original batch.
func TestBacklogWindowsW512TwoGiBByteBound(t *testing.T) {
    sizes := make([]int, 24)
    for i := range sizes {
        sizes[i] = 8192
    }
    g := backlogWindowFixture(sizes, 96<<20)
    limits := BacklogWindowLimits{MaxRecords: 524288, MaxDataBytes: 2 << 30}
    got, err := PlanBacklogWindows(g, limits)
    if err != nil {
        t.Fatal(err)
    }
    want := []BacklogWindow{
        {StartBatch: 0, EndBatch: 21, StartRecord: 0, EndRecord: 172032, DataBytes: 2016 << 20},
        {StartBatch: 21, EndBatch: 24, StartRecord: 172032, EndRecord: 196608, DataBytes: 288 << 20},
    }
    if !reflect.DeepEqual(got, want) {
        t.Fatalf("W512 byte-budget grouping: got=%+v want=%+v", got, want)
    }
}

// TestBacklogWindowsW512TwoGiBExactByteLimit verifies that an original
// signed batch may bring the exact 2 GiB bound but cannot cross it.
func TestBacklogWindowsW512TwoGiBExactByteLimit(t *testing.T) {
    sizes := make([]int, 33)
    for i := range sizes {
        sizes[i] = 8192
    }
    g := backlogWindowFixture(sizes, 64<<20)
    got, err := PlanBacklogWindows(g, BacklogWindowLimits{MaxRecords: 524288, MaxDataBytes: 2 << 30})
    if err != nil {
        t.Fatal(err)
    }
    want := []BacklogWindow{
        {StartBatch: 0, EndBatch: 32, StartRecord: 0, EndRecord: 262144, DataBytes: 2 << 30},
        {StartBatch: 32, EndBatch: 33, StartRecord: 262144, EndRecord: 270336, DataBytes: 64 << 20},
    }
    if !reflect.DeepEqual(got, want) {
        t.Fatalf("W512 exact 2GiB byte-limit: got=%+v want=%+v", got, want)
    }
}
