//go:build fi_c1_sor_dev

package recordingest

import (
    "bytes"
    "testing"
    "time"
)

func TestC1CommittedReplaySourceIdentityCompare(t *testing.T){
    frame:=c1SQLTestFrame(1,1)
    prepared,err:=PrepareSourceRecord(frame.Rows[0].RawRecord)
    if err!=nil{t.Fatal(err)}
    row:=privateP6Record{signedBatchIndex:0,sourceBatchID:55,
        ordinal:1,prepared:prepared}
    existing:=c1PersistedSourceIdentity{
        ID:123,Version:prepared.Record.Version,
        Kind:prepared.Record.RecordKind,Scope:prepared.Record.ScopeID,
        WrittenAt:prepared.WrittenAtUTC,Bytes:int64(prepared.RecordBytes),
        Digest:bytes.Clone(prepared.RecordDigest[:]),TypedRoot:true,
    }
    result,err:=c1VerifyPersistedSourceIdentity(row,existing)
    if err!=nil||result.SourceRecordID!=123||!result.ParentCommitted||
        !result.TypedRootCommitted{
        t.Fatalf("correct durable row not recognized: state=%+v err=%v",result,err)
    }
    missing,err:=c1VerifyPersistedSourceIdentity(row,c1PersistedSourceIdentity{})
    if err!=nil||missing.ParentCommitted||missing.TypedRootCommitted{
        t.Fatalf("missing parent is not a committed checkpoint: %+v err=%v",missing,err)
    }
}
func TestC1CommittedReplayRejectsConflictingSourceIdentity(t *testing.T){
    frame:=c1SQLTestFrame(1,1)
    source,err:=PrepareSourceRecord(frame.Rows[0].RawRecord)
    if err!=nil{t.Fatal(err)}
    row:=privateP6Record{signedBatchIndex:0,sourceBatchID:55,ordinal:1,prepared:source}
    reference:=c1PersistedSourceIdentity{
        ID:345,Version:source.Record.Version,Kind:source.Record.RecordKind,
        Scope:source.Record.ScopeID,WrittenAt:source.WrittenAtUTC,
        Bytes:int64(source.RecordBytes),Digest:bytes.Clone(source.RecordDigest[:]),
        TypedRoot:true,
    }
    tests:=map[string]func(*c1PersistedSourceIdentity){
        "digest":func(s *c1PersistedSourceIdentity){s.Digest[0]^=1},
        "bytes":func(s *c1PersistedSourceIdentity){s.Bytes++},
        "kind":func(s *c1PersistedSourceIdentity){s.Kind="FileObservation"},
        "scope":func(s *c1PersistedSourceIdentity){s.Scope="foreign"},
        "version":func(s *c1PersistedSourceIdentity){s.Version="wrong"},
        "written":func(s *c1PersistedSourceIdentity){s.WrittenAt=s.WrittenAt.Add(time.Second)},
        "orphan-typed":func(s *c1PersistedSourceIdentity){s.ID=0;s.TypedRoot=true},
    }
    for name,mutate:=range tests{
        t.Run(name,func(t *testing.T){
            record:=reference
            record.Digest=bytes.Clone(reference.Digest)
            mutate(&record)
            if _,err:=c1VerifyPersistedSourceIdentity(row,record);err==nil{
                t.Fatal("unsafe replay of conflicting previously committed source accepted")
            }
        })
    }
}
