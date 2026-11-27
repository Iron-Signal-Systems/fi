//go:build fi_c1_sor_dev

package recordingest

import (
    "bytes"
    "testing"
    "time"

    "github.com/Iron-Signal-Systems/fi/go/internal/c1handoff"
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

func TestC1RecoveredSourceAndTypedHandoffSelection(t *testing.T){
    frame:=c1SQLTestFrame(c1handoff.Source,1)
    source,err:=PrepareSourceRecord(frame.Rows[0].RawRecord)
    if err!=nil{t.Fatal(err)}
    rows:=[]privateP6Record{
        {signedBatchIndex:0,sourceBatchID:55,ordinal:1,prepared:source},
        {signedBatchIndex:0,sourceBatchID:55,ordinal:2,prepared:source},
        {signedBatchIndex:0,sourceBatchID:55,ordinal:3,prepared:source},
    }
    states:=[]C1RecoveryRowState{
        {SourceRecordID:91,ParentCommitted:true,TypedRootCommitted:true},
        {SourceRecordID:92,ParentCommitted:true,TypedRootCommitted:false},
        {},
    }
    parents,err:=c1PartitionRecoveredHandoff(c1handoff.Source,rows,states)
    if err!=nil{t.Fatal(err)}
    if len(parents.AlreadyCommitted)!=2||len(parents.MustWrite)!=1||
        parents.MustWrite[0].ordinal!=3{
        t.Fatal("SourceParent replay failed to preserve original signed identity/order")
    }
    typed,err:=c1PartitionRecoveredHandoff(c1handoff.Other,rows,states)
    if err!=nil{t.Fatal(err)}
    if len(typed.AlreadyCommitted)!=1||len(typed.MustWrite)!=2||
        typed.MustWrite[0].ordinal!=2||typed.MustWrite[1].ordinal!=3{
        t.Fatal("typed SQL replay must write only incomplete original typed roots")
    }
    states[1]=C1RecoveryRowState{TypedRootCommitted:true}
    if _,err=c1PartitionRecoveredHandoff(c1handoff.Other,rows,states);err==nil{
        t.Fatal("typed family accepted impossible committed root without parent")
    }
}
func TestC1RecoveredHandoffRejectsWrongFamilyAndDuplicate(t *testing.T){
    frame:=c1SQLTestFrame(c1handoff.Source,1)
    source,err:=PrepareSourceRecord(frame.Rows[0].RawRecord)
    if err!=nil{t.Fatal(err)}
    row:=privateP6Record{signedBatchIndex:0,sourceBatchID:55,ordinal:1,prepared:source}
    if _,err=c1PartitionRecoveredHandoff(c1handoff.Security,
        []privateP6Record{row},[]C1RecoveryRowState{{}});err==nil{
        t.Fatal("wrong typed projector selected after restart")
    }
    if _,err=c1PartitionRecoveredHandoff(c1handoff.Source,
        []privateP6Record{row,row},[]C1RecoveryRowState{{},{}});err==nil{
        t.Fatal("duplicate original signed source row accepted")
    }
}


func TestC1SignedNanosecondWrittenAtSurvivesPostgresMicrosecondStorage(t *testing.T) {
    // This is a real recorder-supported RFC3339Nano timestamp. PostgreSQL
    // timestamptz stores 6 fractional digits, while the signed JSONL SHA
    // still binds all 9 original fractional digits.
    raw:=[]byte("{\"version\":\"fi-spool-record/0.1\",\"record_kind\":\"CollectorIdentity\",\"scope_id\":\"c1-microsecond\",\"written_at\":\"2026-11-22T14:57:12.123456789Z\",\"payload\":{\"name\":\"real-source\"}}\n")
    prepared,err:=PrepareSourceRecord(raw)
    if err!=nil{t.Fatal(err)}
    if prepared.WrittenAtUTC.Nanosecond()!=123456789 {
        t.Fatalf("original signed nanosecond timestamp changed before SQL: %s",prepared.WrittenAtUTC)
    }
    signed:=privateP6Record{sourceBatchID:55,ordinal:1,prepared:prepared}
    stored:=c1PersistedSourceIdentity{
        ID:123,Version:prepared.Record.Version,Kind:prepared.Record.RecordKind,
        Scope:prepared.Record.ScopeID,WrittenAt:prepared.WrittenAtUTC.Truncate(time.Microsecond),
        Bytes:int64(prepared.RecordBytes),Digest:bytes.Clone(prepared.RecordDigest[:]),
        TypedRoot:true,
    }
    state,err:=c1VerifyPersistedSourceIdentity(signed,stored)
    if err!=nil||!state.ParentCommitted||!state.TypedRootCommitted {
        t.Fatalf("C1 falsely rejects original signed nanosecond time at PostgreSQL exact storage precision: %+v %v",state,err)
    }
    modifiedTime:=stored
    modifiedTime.WrittenAt=stored.WrittenAt.Add(time.Microsecond)
    if _,err=c1VerifyPersistedSourceIdentity(signed,modifiedTime);err==nil{
        t.Fatal("C1 accepted a real changed PostgreSQL timestamp")
    }
    modifiedDigest:=stored
    modifiedDigest.Digest=bytes.Clone(stored.Digest)
    modifiedDigest.Digest[0]^=1
    if _,err=c1VerifyPersistedSourceIdentity(signed,modifiedDigest);err==nil{
        t.Fatal("C1 accepted a changed original signed JSONL digest")
    }
}
