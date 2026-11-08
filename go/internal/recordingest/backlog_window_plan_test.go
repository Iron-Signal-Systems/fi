// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
)

func backlogWindowFixture(sizes []int, dataBytes int64) *PreparedGeneration {
	g := &PreparedGeneration{Batches: make([]PreparedBatch, 0, len(sizes))}
	for i, n := range sizes {
		id := fmt.Sprintf("%032d", i+1)
		g.Batches = append(g.Batches, PreparedBatch{
			BatchID:  id,
			Manifest: spool.Manifest{BatchID: id, DataFile: "batch-" + id + ".jsonl", TargetBatchSize: n, RecordCount: n, DataBytes: dataBytes},
		})
		g.Receipt.RecordCount += uint64(n)
		g.Receipt.DataBytes += uint64(dataBytes)
		g.Receipt.BatchCount++
	}
	return g
}

func TestBacklogWindows32KAnd64KRespectOriginalBatchBoundaries(t *testing.T) {
	g := backlogWindowFixture([]int{8192, 8192, 8192, 8192, 8192, 8192, 8192, 8192, 8192}, 16<<20)
	beforeReceipt := g.Receipt
	beforeBatches := append([]PreparedBatch(nil), g.Batches...)
	p32, err := PlanBacklogWindows(g, BacklogWindowLimits{MaxRecords: 32768, MaxDataBytes: 256 << 20})
	if err != nil {
		t.Fatal(err)
	}
	p64, err := PlanBacklogWindows(g, BacklogWindowLimits{MaxRecords: 65536, MaxDataBytes: 256 << 20})
	if err != nil {
		t.Fatal(err)
	}
	want32 := []BacklogWindow{
		{StartBatch: 0, EndBatch: 4, StartRecord: 0, EndRecord: 32768, DataBytes: 64 << 20},
		{StartBatch: 4, EndBatch: 8, StartRecord: 32768, EndRecord: 65536, DataBytes: 64 << 20},
		{StartBatch: 8, EndBatch: 9, StartRecord: 65536, EndRecord: 73728, DataBytes: 16 << 20},
	}
	want64 := []BacklogWindow{
		{StartBatch: 0, EndBatch: 8, StartRecord: 0, EndRecord: 65536, DataBytes: 128 << 20},
		{StartBatch: 8, EndBatch: 9, StartRecord: 65536, EndRecord: 73728, DataBytes: 16 << 20},
	}
	if !reflect.DeepEqual(p32, want32) || !reflect.DeepEqual(p64, want64) {
		t.Fatalf("32K=%+v 64K=%+v", p32, p64)
	}
	if !reflect.DeepEqual(beforeReceipt, g.Receipt) || !reflect.DeepEqual(beforeBatches, g.Batches) {
		t.Fatal("planner modified original signed-generation metadata")
	}
}

func TestBacklogWindowsByteBudgetAndOversizedBatch(t *testing.T) {
	g := backlogWindowFixture([]int{8192, 8192, 8192}, 50<<20)
	w, err := PlanBacklogWindows(g, BacklogWindowLimits{MaxRecords: 65536, MaxDataBytes: 90 << 20})
	if err != nil || len(w) != 3 {
		t.Fatalf("byte budget windows=%+v err=%v", w, err)
	}
	_, err = PlanBacklogWindows(g, BacklogWindowLimits{MaxRecords: 65536, MaxDataBytes: 40 << 20})
	if err == nil || !strings.Contains(err.Error(), "exceeds window budget") {
		t.Fatalf("oversized batch not rejected: %v", err)
	}
}

func TestBacklogWindowsRejectReceiptMismatchAndDuplicateBatches(t *testing.T) {
	g := backlogWindowFixture([]int{8192, 8192}, 1<<20)
	lim := BacklogWindowLimits{MaxRecords: 65536, MaxDataBytes: 64 << 20}
	g.Receipt.RecordCount++
	if _, err := PlanBacklogWindows(g, lim); err == nil {
		t.Fatal("mismatched signed receipt accepted")
	}
	g.Receipt.RecordCount--
	g.Batches[1].BatchID = g.Batches[0].BatchID
	g.Batches[1].Manifest.BatchID = g.Batches[0].BatchID
	g.Batches[1].Manifest.DataFile = g.Batches[0].Manifest.DataFile
	if _, err := PlanBacklogWindows(g, lim); err == nil {
		t.Fatal("duplicate source batch accepted")
	}
}

func TestBacklogWindowsFailClosed(t *testing.T) {
	if _, err := PlanBacklogWindows(nil, BacklogWindowLimits{1, 1}); err == nil {
		t.Fatal("nil generation accepted")
	}
	g := backlogWindowFixture([]int{1}, 1)
	if _, err := PlanBacklogWindows(g, BacklogWindowLimits{}); err == nil {
		t.Fatal("zero budgets accepted")
	}
	if _, err := PlanBacklogWindows(g, BacklogWindowLimits{1, 1}); err != nil {
		t.Fatal(err)
	}
}

func TestBacklogWindows128KOneGiBLimits(t *testing.T) {
	countFixture := backlogWindowFixture([]int{
		8192, 8192, 8192, 8192, 8192, 8192, 8192, 8192,
		8192, 8192, 8192, 8192, 8192, 8192, 8192, 8192, 8192,
	}, 32<<20)
	originalReceipt := countFixture.Receipt
	limits := BacklogWindowLimits{MaxRecords: 131072, MaxDataBytes: 1 << 30}
	countWindows, err := PlanBacklogWindows(countFixture, limits)
	if err != nil {
		t.Fatal(err)
	}
	wantCount := []BacklogWindow{
		{StartBatch: 0, EndBatch: 16, StartRecord: 0, EndRecord: 131072, DataBytes: 512 << 20},
		{StartBatch: 16, EndBatch: 17, StartRecord: 131072, EndRecord: 139264, DataBytes: 32 << 20},
	}
	if !reflect.DeepEqual(countWindows, wantCount) {
		t.Fatalf("W128 count bound: got=%+v want=%+v", countWindows, wantCount)
	}
	if !reflect.DeepEqual(countFixture.Receipt, originalReceipt) {
		t.Fatal("W128 planner mutated signed receipt")
	}

	byteFixture := backlogWindowFixture([]int{
		8192, 8192, 8192, 8192, 8192, 8192,
		8192, 8192, 8192, 8192, 8192, 8192,
	}, 96<<20)
	byteWindows, err := PlanBacklogWindows(byteFixture, limits)
	if err != nil {
		t.Fatal(err)
	}
	wantBytes := []BacklogWindow{
		{StartBatch: 0, EndBatch: 10, StartRecord: 0, EndRecord: 81920, DataBytes: 960 << 20},
		{StartBatch: 10, EndBatch: 12, StartRecord: 81920, EndRecord: 98304, DataBytes: 192 << 20},
	}
	if !reflect.DeepEqual(byteWindows, wantBytes) {
		t.Fatalf("W128 byte bound: got=%+v want=%+v", byteWindows, wantBytes)
	}
}

func TestBacklogWindows32K64K96K128KSeparatePlans(t *testing.T) {
	counts := make([]int, 17)
	for i := range counts {
		counts[i] = 8192
	}
	g := backlogWindowFixture(counts, 32<<20)
	profiles := []BacklogWindowLimits{
		{MaxRecords: 32768, MaxDataBytes: 256 << 20},
		{MaxRecords: 65536, MaxDataBytes: 1 << 30},
		{MaxRecords: 98304, MaxDataBytes: 1 << 30},
		{MaxRecords: 131072, MaxDataBytes: 1 << 30},
	}
	expected := []int{5, 3, 2, 2}
	for i, limits := range profiles {
		windows, err := PlanBacklogWindows(g, limits)
		if err != nil {
			t.Fatal(err)
		}
		if len(windows) != expected[i] {
			t.Errorf("%d record max: got %d windows, want %d", limits.MaxRecords, len(windows), expected[i])
		}
	}
}
// W256 is a separate immutable checkpoint plan, never a relabelled W128
// prefix. Signed batches must remain intact under both independent budgets.
func TestBacklogWindowsW256TwoGiBBounds(t *testing.T) {
	counts := make([]int, 35)
	for i := range counts {
		counts[i] = 8192
	}
	g := backlogWindowFixture(counts, 32<<20)
	before := g.Receipt
	lim := BacklogWindowLimits{MaxRecords: 262144, MaxDataBytes: 2 << 30}
	got, err := PlanBacklogWindows(g, lim)
	if err != nil {
		t.Fatal(err)
	}
	want := []BacklogWindow{
		{StartBatch: 0, EndBatch: 32, StartRecord: 0, EndRecord: 262144, DataBytes: 1 << 30},
		{StartBatch: 32, EndBatch: 35, StartRecord: 262144, EndRecord: 286720, DataBytes: 96 << 20},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("W256 record cap: got=%+v want=%+v", got, want)
	}
	if !reflect.DeepEqual(before, g.Receipt) {
		t.Fatal("W256 plan modified signed receipt")
	}
	byBytes := backlogWindowFixture(counts[:12], 192<<20)
	got, err = PlanBacklogWindows(byBytes, lim)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].EndBatch != 10 ||
		got[0].DataBytes != 1920<<20 || got[1].DataBytes != 384<<20 {
		t.Fatalf("W256 2GiB byte ceiling not enforced at intact batch: %+v", got)
	}
}

