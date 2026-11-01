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
			BatchID: id,
			Manifest: spool.Manifest{BatchID: id, DataFile: "batch-"+id+".jsonl", TargetBatchSize: n, RecordCount: n, DataBytes: dataBytes},
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
	p32, err := PlanBacklogWindows(g, BacklogWindowLimits{MaxRecords: 32768, MaxDataBytes: 256<<20})
	if err != nil { t.Fatal(err) }
	p64, err := PlanBacklogWindows(g, BacklogWindowLimits{MaxRecords: 65536, MaxDataBytes: 256<<20})
	if err != nil { t.Fatal(err) }
	want32 := []BacklogWindow{
		{StartBatch: 0, EndBatch: 4, StartRecord: 0, EndRecord: 32768, DataBytes: 64<<20},
		{StartBatch: 4, EndBatch: 8, StartRecord: 32768, EndRecord: 65536, DataBytes: 64<<20},
		{StartBatch: 8, EndBatch: 9, StartRecord: 65536, EndRecord: 73728, DataBytes: 16<<20},
	}
	want64 := []BacklogWindow{
		{StartBatch: 0, EndBatch: 8, StartRecord: 0, EndRecord: 65536, DataBytes: 128<<20},
		{StartBatch: 8, EndBatch: 9, StartRecord: 65536, EndRecord: 73728, DataBytes: 16<<20},
	}
	if !reflect.DeepEqual(p32,want32) || !reflect.DeepEqual(p64,want64) { t.Fatalf("32K=%+v 64K=%+v", p32,p64) }
	if !reflect.DeepEqual(beforeReceipt,g.Receipt) || !reflect.DeepEqual(beforeBatches,g.Batches) { t.Fatal("planner modified original signed-generation metadata") }
}

func TestBacklogWindowsByteBudgetAndOversizedBatch(t *testing.T) {
	g := backlogWindowFixture([]int{8192,8192,8192}, 50<<20)
	w,err := PlanBacklogWindows(g,BacklogWindowLimits{MaxRecords:65536,MaxDataBytes:90<<20})
	if err!=nil || len(w)!=3 { t.Fatalf("byte budget windows=%+v err=%v",w,err) }
	_,err=PlanBacklogWindows(g,BacklogWindowLimits{MaxRecords:65536,MaxDataBytes:40<<20})
	if err==nil || !strings.Contains(err.Error(),"exceeds window budget") { t.Fatalf("oversized batch not rejected: %v",err) }
}

func TestBacklogWindowsRejectReceiptMismatchAndDuplicateBatches(t *testing.T) {
	g:=backlogWindowFixture([]int{8192,8192},1<<20)
	lim:=BacklogWindowLimits{MaxRecords:65536,MaxDataBytes:64<<20}
	g.Receipt.RecordCount++
	if _,err:=PlanBacklogWindows(g,lim);err==nil { t.Fatal("mismatched signed receipt accepted") }
	g.Receipt.RecordCount--
	g.Batches[1].BatchID=g.Batches[0].BatchID
	g.Batches[1].Manifest.BatchID=g.Batches[0].BatchID
	g.Batches[1].Manifest.DataFile=g.Batches[0].Manifest.DataFile
	if _,err:=PlanBacklogWindows(g,lim);err==nil { t.Fatal("duplicate source batch accepted") }
}

func TestBacklogWindowsFailClosed(t *testing.T) {
	if _,err:=PlanBacklogWindows(nil,BacklogWindowLimits{1,1});err==nil { t.Fatal("nil generation accepted") }
	g:=backlogWindowFixture([]int{1},1)
	if _,err:=PlanBacklogWindows(g,BacklogWindowLimits{});err==nil { t.Fatal("zero budgets accepted") }
	if _,err:=PlanBacklogWindows(g,BacklogWindowLimits{1,1});err!=nil { t.Fatal(err) }
}
