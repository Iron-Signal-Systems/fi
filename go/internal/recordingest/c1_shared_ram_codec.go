//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Exact C1 P5 prepared values cross the jail boundary by immutable tmpfs
// object. Only the object reference crosses the authenticated mTLS channel.
// The original raw JSONL bytes/digest are preserved for independent proof.
package recordingest

import (
    "bytes"
    "crypto/sha256"
    "encoding/gob"
    "encoding/hex"
    "errors"
    "fmt"
    "io"
    "math/big"
    "time"

    "github.com/Iron-Signal-Systems/fi/go/internal/c1handoff"
    "github.com/Iron-Signal-Systems/fi/go/internal/records"
    "github.com/Iron-Signal-Systems/fi/go/internal/spool"
    "github.com/jackc/pgx/v5/pgtype"
)

type c1RAMSource struct {
    Record spool.Record
    Raw []byte
    Digest [32]byte
    WrittenAt time.Time
}
type c1RAMRow struct {
    BatchIndex uint32
    BatchID int64
    Ordinal int64
    Source c1RAMSource
    FileSelected bool
    FileValue fileObservationPayload
    CoverageSelected bool
    CoverageValue records.WindowsSecurityCoverageObservation
    CoverageObservedAt time.Time
    SecuritySelected bool
    SecurityValue records.WindowsSecurityEventObservation
    SecurityObservedAt time.Time
    SecurityTimeCreated time.Time
    SecurityEventID int64
    SecurityEventRecordID string
}
type c1RAMEnvelope struct {
    Version uint16
    Rows []c1RAMRow
}

func encodeC1PreparedRAMRows(rows []privateP6Record)([]byte,error){
    if len(rows)==0||len(rows)>c1handoff.MaxRows{
        return nil,errors.New("C1 RAM: prepared rows outside original C1 P6 limits")
    }
    out:=c1RAMEnvelope{Version:1,Rows:make([]c1RAMRow,0,len(rows))}
    for i,r:=range rows{
        if !r.valid() || r.signedBatchIndex>65535{
            return nil,fmt.Errorf("C1 RAM: invalid or unsupported prepared provenance at %d",i)
        }
        if sha256.Sum256(r.prepared.RawRecordBytes)!=r.prepared.RecordDigest {
            return nil,errors.New("C1 RAM: source digest differs from verified original bytes")
        }
        record:=c1RAMRow{BatchIndex:uint32(r.signedBatchIndex),
            BatchID:r.sourceBatchID,Ordinal:r.ordinal,
            Source:c1RAMSource{Record:r.prepared.Record,
                Raw:r.prepared.RawRecordBytes,Digest:r.prepared.RecordDigest,
                WrittenAt:r.prepared.WrittenAtUTC}}
        switch r.prepared.Record.RecordKind {
        case "FileObservation":
            if r.prepared.PrivateFamilyP3File==nil{
                return nil,errors.New("C1 RAM: File missing original validated P5 preparation")
            }
            record.FileSelected=true
            record.FileValue=*r.prepared.PrivateFamilyP3File
        case "WindowsSecurityCoverage":
            if r.prepared.PrivateFamilyP3Coverage==nil||
                r.prepared.PrivateFamilyP3Coverage.observedAt.IsZero(){
                return nil,errors.New("C1 RAM: Coverage missing original validated P5 preparation")
            }
            record.CoverageSelected=true
            record.CoverageValue=r.prepared.PrivateFamilyP3Coverage.value
            record.CoverageObservedAt=r.prepared.PrivateFamilyP3Coverage.observedAt
        case "WindowsSecurityEvent":
            if !r.selectedSinglePass ||
                r.singlePassSecurity.prepared.RecordDigest!=r.prepared.RecordDigest ||
                !r.singlePassSecurity.eventRecordID.Valid ||
                r.singlePassSecurity.eventRecordID.Int==nil{
                return nil,errors.New("C1 RAM: Security must preserve original P5 single-pass preparation")
            }
            record.SecuritySelected=true
            record.SecurityValue=r.singlePassSecurity.value
            record.SecurityObservedAt=r.singlePassSecurity.observedAt
            record.SecurityTimeCreated=r.singlePassSecurity.timeCreated
            record.SecurityEventID=r.singlePassSecurity.eventID
            record.SecurityEventRecordID=r.singlePassSecurity.eventRecordID.Int.String()
        default:
            if r.prepared.PrivateFamilyP3File!=nil||r.prepared.PrivateFamilyP3Coverage!=nil{
                return nil,errors.New("C1 RAM: wrong P5 family provenance attached to other source")
            }
        }
        if r.prepared.Record.RecordKind!="WindowsSecurityEvent" && r.selectedSinglePass{
            return nil,errors.New("C1 RAM: non-Security record claims Security single pass")
        }
        if (r.prepared.Record.RecordKind!="FileObservation"&&r.prepared.PrivateFamilyP3File!=nil)||
           (r.prepared.Record.RecordKind!="WindowsSecurityCoverage"&&r.prepared.PrivateFamilyP3Coverage!=nil){
            return nil,errors.New("C1 RAM: crossed prepared File/Coverage family provenance")
        }
        out.Rows=append(out.Rows,record)
    }
    var buf bytes.Buffer
    if err:=gob.NewEncoder(&buf).Encode(out);err!=nil{return nil,err}
    if buf.Len()==0||buf.Len()>c1handoff.MaxSharedRAMObjectBytes {
        return nil,errors.New("C1 RAM: encoded P5 output exceeds bounded tmpfs object size")
    }
    return buf.Bytes(),nil
}

func decodeC1PreparedRAMRows(data []byte)([]privateP6Record,error){
    if len(data)==0||len(data)>c1handoff.MaxSharedRAMObjectBytes{
        return nil,errors.New("C1 RAM: invalid prepared object length")
    }
    reader:=bytes.NewReader(data)
    decoder:=gob.NewDecoder(reader)
    var in c1RAMEnvelope
    if err:=decoder.Decode(&in);err!=nil{return nil,fmt.Errorf("C1 RAM: prepared decode: %w",err)}
    var excess any
    if err:=decoder.Decode(&excess);err!=io.EOF{
        return nil,errors.New("C1 RAM: extra or corrupted trailing payload")
    }
    if in.Version!=1||len(in.Rows)==0||len(in.Rows)>c1handoff.MaxRows{
        return nil,errors.New("C1 RAM: incorrect prepared format or row count")
    }
    result:=make([]privateP6Record,0,len(in.Rows))
    for i,w:=range in.Rows{
        if w.BatchIndex>65535||w.BatchID<=0||w.Ordinal<=0||
            len(w.Source.Raw)<2||len(w.Source.Raw)>c1handoff.MaxSingleRecordBytes||
            w.Source.Raw[len(w.Source.Raw)-1]!='\n'||
            sha256.Sum256(w.Source.Raw)!=w.Source.Digest{
            return nil,fmt.Errorf("C1 RAM: original source digest/identity invalid at row %d",i)
        }
        if w.Source.Record.Version!=SpoolRecordVersion||
            w.Source.Record.ScopeID==""||w.Source.Record.RecordKind==""||
            w.Source.Record.WrittenAt==""||len(w.Source.Record.Payload)==0||
            w.Source.WrittenAt.IsZero(){
            return nil,errors.New("C1 RAM: original source envelope not prepared")
        }
        prepared:=SourceRecord{Record:w.Source.Record,
            RawRecordBytes:w.Source.Raw,RecordBytes:len(w.Source.Raw),
            RecordDigest:w.Source.Digest,
            RecordSHA256:hex.EncodeToString(w.Source.Digest[:]),
            WrittenAtUTC:w.Source.WrittenAt}
        record:=privateP6Record{signedBatchIndex:int(w.BatchIndex),
            sourceBatchID:w.BatchID,ordinal:w.Ordinal,prepared:prepared}
        if w.FileSelected{
            if prepared.Record.RecordKind!="FileObservation"||w.SecuritySelected||w.CoverageSelected{
                return nil,errors.New("C1 RAM: original validated File P5 family mismatches spool kind")
            }
            prepared.PrivateFamilyP3File=&w.FileValue
            record.prepared=prepared
        }
        if w.CoverageSelected{
            if prepared.Record.RecordKind!="WindowsSecurityCoverage"||
                w.SecuritySelected||w.FileSelected||w.CoverageObservedAt.IsZero(){
                return nil,errors.New("C1 RAM: original validated Coverage P5 family mismatches spool kind")
            }
            prepared.PrivateFamilyP3Coverage=&privateFamilyP3CoverageValue{
                value:w.CoverageValue,observedAt:w.CoverageObservedAt,
            }
            record.prepared=prepared
        }
        if (prepared.Record.RecordKind=="FileObservation"&&!w.FileSelected)||
           (prepared.Record.RecordKind=="WindowsSecurityCoverage"&&!w.CoverageSelected){
            return nil,errors.New("C1 RAM: validated File/Coverage provenance absent")
        }
        if w.Source.Record.RecordKind=="WindowsSecurityEvent"{
            n,ok:=new(big.Int).SetString(w.SecurityEventRecordID,10)
            if !w.SecuritySelected||!ok||n.Sign()<0||
                w.SecurityEventID<0||w.SecurityObservedAt.IsZero()||
                w.SecurityTimeCreated.IsZero(){
                return nil,errors.New("C1 RAM: Security single-pass validation was lost")
            }
            record.selectedSinglePass=true
            record.singlePassSecurity=securityBulkRecord{
                sourceBatchID:w.BatchID,ordinal:w.Ordinal,
                prepared:prepared,digest:prepared.RecordDigest[:],
                value:w.SecurityValue,observedAt:w.SecurityObservedAt,
                timeCreated:w.SecurityTimeCreated,eventID:w.SecurityEventID,
                eventRecordID:pgtype.Numeric{Int:n,Exp:0,Valid:true},
            }
        }else if w.SecuritySelected{
            return nil,errors.New("C1 RAM: wrong prepared family in shared object")
        }
        if !record.valid(){return nil,errors.New("C1 RAM: decoded prepared source invalid")}
        result=append(result,record)
    }
    return result,nil
}
