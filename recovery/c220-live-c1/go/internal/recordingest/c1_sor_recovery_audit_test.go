//go:build fi_c1_sor_dev

package recordingest

import ("testing";"errors")

func TestC1RecoverySourcePrefixClassification(t *testing.T){
    original:=[]C1RecoveryBatchEvidence{
        {Index:0,BatchID:"a",SourceBatchID:10,SignedRecords:3,SignedBytes:30,
            ParentRows:3,ParentDistinctOrdinals:3,ParentBytes:30,MinOrdinal:1,MaxOrdinal:3},
        {Index:1,BatchID:"b",SourceBatchID:11,SignedRecords:2,SignedBytes:20,
            ParentRows:2,ParentDistinctOrdinals:2,ParentBytes:20,MinOrdinal:1,MaxOrdinal:2},
        {Index:2,BatchID:"c",SourceBatchID:12,SignedRecords:4,SignedBytes:40},
    }
    prefix,dirty,total,err:=c1ClassifyRecoverySourcePrefix(original)
    if err!=nil||prefix!=2||dirty||total!=5{
        t.Fatalf("clean complete prefix: prefix=%d dirty=%t total=%d err=%v",prefix,dirty,total,err)
    }
    original[2].ParentRows=2
    original[2].ParentDistinctOrdinals=2
    original[2].ParentBytes=20
    original[2].MinOrdinal=1
    original[2].MaxOrdinal=2
    prefix,dirty,total,err=c1ClassifyRecoverySourcePrefix(original)
    if err!=nil||prefix!=2||!dirty||total!=7{
        t.Fatalf("partial current batch: prefix=%d dirty=%t total=%d err=%v",prefix,dirty,total,err)
    }
}
func TestC1RecoveryRejectsNoncontiguousPartialCommit(t *testing.T){
    cases:=map[string][]C1RecoveryBatchEvidence{
        "gap-in-ordinal":{{Index:0,BatchID:"a",SourceBatchID:1,SignedRecords:5,SignedBytes:50,
            ParentRows:2,ParentDistinctOrdinals:2,ParentBytes:20,MinOrdinal:1,MaxOrdinal:3}},
        "duplicate-ordinal":{{Index:0,BatchID:"a",SourceBatchID:1,SignedRecords:5,SignedBytes:50,
            ParentRows:2,ParentDistinctOrdinals:1,ParentBytes:20,MinOrdinal:1,MaxOrdinal:1}},
        "committed-bytes-conflict":{{Index:0,BatchID:"a",SourceBatchID:1,SignedRecords:2,SignedBytes:20,
            ParentRows:2,ParentDistinctOrdinals:2,ParentBytes:19,MinOrdinal:1,MaxOrdinal:2}},
        "overcommitted":{{Index:0,BatchID:"a",SourceBatchID:1,SignedRecords:2,SignedBytes:20,
            ParentRows:3,ParentDistinctOrdinals:3,ParentBytes:20,MinOrdinal:1,MaxOrdinal:3}},
        "after-incomplete-batch":{
            {Index:0,BatchID:"a",SourceBatchID:1,SignedRecords:5,SignedBytes:50},
            {Index:1,BatchID:"b",SourceBatchID:2,SignedRecords:2,SignedBytes:20,
                ParentRows:1,ParentDistinctOrdinals:1,ParentBytes:10,MinOrdinal:1,MaxOrdinal:1},
        },
        "after-partial-batch":{
            {Index:0,BatchID:"a",SourceBatchID:1,SignedRecords:5,SignedBytes:50,
                ParentRows:1,ParentDistinctOrdinals:1,ParentBytes:10,MinOrdinal:1,MaxOrdinal:1},
            {Index:1,BatchID:"b",SourceBatchID:2,SignedRecords:2,SignedBytes:20,
                ParentRows:1,ParentDistinctOrdinals:1,ParentBytes:10,MinOrdinal:1,MaxOrdinal:1},
        },
    }
    for name,items:=range cases{
        t.Run(name,func(t *testing.T){
            if _,_,_,err:=c1ClassifyRecoverySourcePrefix(items);err==nil{
                t.Fatal("unsafe or inconsistent recovery evidence accepted")
            }
        })
    }
}

func TestC1RecoveryTypedPrefixRequiresAllCommittedRoots(t *testing.T){
    for _,tc:=range []struct{name string;complete,expected int}{
        {"none",0,0},{"all",8,8},{"first-two",8,2},{"only-one",5,1},
    }{
        t.Run(tc.name,func(t *testing.T){
            seen:=0
            n,err:=c1FindReadOnlyTypedPrefix(tc.complete,func(prefix int)error{
                seen++
                if prefix>tc.expected{return ErrSourceRecordRejected}
                return nil
            })
            if err!=nil||n!=tc.expected{
                t.Fatalf("source/typed prefix mismatch got=%d want=%d err=%v",n,tc.expected,err)
            }
            if seen>5{
                t.Fatalf("C1 recovery used too many read-only group checks: %d",seen)
            }
        })
    }
}
func TestC1RecoveryTypedPrefixRefusesUnexpectedSQLFailure(t *testing.T){
    _,err:=c1FindReadOnlyTypedPrefix(4,func(int)error{
        return errors.New("PostgreSQL permission denied")
    })
    if err==nil{t.Fatal("SQL fault incorrectly classified as missing typed root")}
    if _,err=c1FindReadOnlyTypedPrefix(3,nil);err==nil{
        t.Fatal("nil PostgreSQL coverage verifier accepted")
    }
}
