package recordingest

import "testing"

func TestTypedChunkBoundaryRejectsInvalidInputs(t *testing.T) {
    for _,v:=range [][3]int{{0,100,32768},{1,-1,32768},{32769,0,32768},{1,32769,32768},{100,100,0}} {
        if _,err:=shouldFinishBacklogTypedChunk(v[0],v[1],v[2]);err==nil { t.Fatalf("accepted %v",v) }
    }
}

func TestBulkSourceBatchIDPreservesOriginalIdentity(t *testing.T) {
    if got := bulkSourceBatchID(42, 7); got != 42 { t.Fatalf("original batch lost: %d",got) }
    if got := bulkSourceBatchID(0, 7); got != 7 { t.Fatalf("legacy batch lost: %d",got) }
}

// The chunk planner must always preserve entire signed batches, including
// uneven real backlog batches, and terminate exactly at the window boundary.
func TestTypedChunkSignedBatchPartition(t *testing.T) {
    batches:=[]int{6500,8000,7200,8100,2000,6400,7300,8000,7900,7000,7600,8100,6900,7800,7100,7600,8000,7500}
    for _,limit:=range []int{32768,65536,98304,131072} {
        pending:=0
        chunks:=0
        total:=0
        for i,n:=range batches {
            if n<=0 || n>limit-pending {t.Fatalf("limit %d batch %d exceeds chunk",limit,i)}
            pending+=n
            next:=0
            if i+1<len(batches){next=batches[i+1]}
            finish,err:=shouldFinishBacklogTypedChunk(pending,next,limit)
            if err!=nil {t.Fatal(err)}
            if finish {
                if pending>limit { t.Fatal("overflow") }
                total+=pending
                chunks++
                pending=0
            }
        }
        if total!=129000 || pending!=0 || chunks<1 {t.Fatalf("limit %d bad partition total=%d pending=%d chunks=%d",limit,total,pending,chunks)}
    }
}
