//go:build fi_c1_sor_dev
package recordingest

import (
    "bytes"
    "crypto/sha256"
    "strings"
    "testing"
    "time"
    "math/big"

    "github.com/Iron-Signal-Systems/fi/go/internal/records"
    "github.com/jackc/pgx/v5/pgtype"
)
func TestC1PreparedRAMCodecPreservesSourceWithoutRePreparation(t *testing.T){
    raw:=[]byte("{\"version\":\"fi-spool-record/0.1\",\"record_kind\":\"CollectorIdentity\",\"scope_id\":\"root\",\"written_at\":\"2026-11-21T19:00:00Z\",\"payload\":{}}\n")
    source,err:=PrepareSourceRecord(raw);if err!=nil{t.Fatal(err)}
    original:=[]privateP6Record{{signedBatchIndex:1,sourceBatchID:42,ordinal:8,prepared:source}}
    blob,err:=encodeC1PreparedRAMRows(original);if err!=nil{t.Fatal(err)}
    rows,err:=decodeC1PreparedRAMRows(blob);if err!=nil{t.Fatal(err)}
    if len(rows)!=1||rows[0].sourceBatchID!=42||rows[0].ordinal!=8||
        rows[0].prepared.RecordDigest!=source.RecordDigest||
        !bytes.Equal(rows[0].prepared.RawRecordBytes,raw)||
        rows[0].prepared.Record.RecordKind!=source.Record.RecordKind{
        t.Fatal("prepared original source lost its exact identity")
    }
    blob[len(blob)-1]^=1
    _=sha256.Sum256(blob) // real RAMStore authenticates entire encoded object
}
func TestC1PreparedRAMRejectsMissingSinglePassSecurity(t *testing.T){
    raw:=[]byte("{\"version\":\"fi-spool-record/0.1\",\"record_kind\":\"WindowsSecurityEvent\",\"scope_id\":\"root\",\"written_at\":\"2026-11-21T19:00:00Z\",\"payload\":{}}\n")
    source,err:=PrepareSourceRecord(raw);if err!=nil{t.Fatal(err)}
    if _,err=encodeC1PreparedRAMRows([]privateP6Record{{
        signedBatchIndex:0,sourceBatchID:42,ordinal:1,prepared:source,
    }});err==nil||!strings.Contains(err.Error(),"single-pass"){
        t.Fatalf("unprepared Security accepted: %v",err)
    }
}

func TestC1PreparedRAMSecuritySinglePassSurvivesJailBoundary(t *testing.T){
    raw:=[]byte("{\"version\":\"fi-spool-record/0.1\",\"record_kind\":\"WindowsSecurityEvent\",\"scope_id\":\"root\",\"written_at\":\"2026-11-21T19:00:00Z\",\"payload\":{}}\n")
    source,err:=PrepareSourceRecord(raw);if err!=nil{t.Fatal(err)}
    date:=time.Date(2026,11,21,19,0,0,0,time.UTC)
    prepared:=securityBulkRecord{prepared:source,
        value:records.WindowsSecurityEventObservation{
            EventID:"4663",EventRecordID:"93016",RawXML:"<event/>",
        },observedAt:date,timeCreated:date,eventID:4663,
        eventRecordID:pgtype.Numeric{Int:big.NewInt(93016),Exp:0,Valid:true},
    }
    row:=privateP6Record{signedBatchIndex:0,sourceBatchID:9,ordinal:3,
        prepared:source,selectedSinglePass:true,singlePassSecurity:prepared}
    blob,err:=encodeC1PreparedRAMRows([]privateP6Record{row})
    if err!=nil{t.Fatalf("Security gob codec: %v",err)}
    decoded,err:=decodeC1PreparedRAMRows(blob)
    if err!=nil{t.Fatalf("Security prepared decode: %v",err)}
    if len(decoded)!=1||!decoded[0].selectedSinglePass||
        decoded[0].singlePassSecurity.value.RawXML!="<event/>"||
        decoded[0].singlePassSecurity.eventRecordID.Int.String()!="93016"||
        decoded[0].singlePassSecurity.eventID!=4663{
        t.Fatal("exact prepared Security values did not cross RAM transport")
    }
}

func TestC1PreparedRAMFileAndCoverageCrossJail(t *testing.T){
    kinds:=[]string{"FileObservation","WindowsSecurityCoverage"}
    for i,kind:=range kinds{
        t.Run(kind,func(t *testing.T){
            raw:=[]byte("{\"version\":\"fi-spool-record/0.1\",\"record_kind\":\""+kind+"\",\"scope_id\":\"root\",\"written_at\":\"2026-11-21T19:00:00Z\",\"payload\":{}}\n")
            prepared,err:=PrepareSourceRecord(raw);if err!=nil{t.Fatal(err)}
            date:=time.Date(2026,11,21,19,0,0,0,time.UTC)
            switch kind{
            case "FileObservation":
                prepared.PrivateFamilyP3File=&fileObservationPayload{}
            case "WindowsSecurityCoverage":
                prepared.PrivateFamilyP3Coverage=&privateFamilyP3CoverageValue{
                    value:records.WindowsSecurityCoverageObservation{
                        ObservedAt:"2026-11-21T19:00:00Z",
                    },observedAt:date,
                }
            }
            original:=[]privateP6Record{{signedBatchIndex:i,sourceBatchID:60+int64(i),
                ordinal:5,prepared:prepared}}
            data,err:=encodeC1PreparedRAMRows(original);if err!=nil{t.Fatal(err)}
            restored,err:=decodeC1PreparedRAMRows(data);if err!=nil{t.Fatal(err)}
            if len(restored)!=1||restored[0].prepared.RecordDigest!=prepared.RecordDigest{
                t.Fatal("original signed File/Coverage record identity lost")
            }
            switch kind{
            case "FileObservation":
                if restored[0].prepared.PrivateFamilyP3File==nil||
                    restored[0].prepared.PrivateFamilyP3Coverage!=nil{
                    t.Fatal("File P5 validated payload not carried across RAM")
                }
            case "WindowsSecurityCoverage":
                got:=restored[0].prepared.PrivateFamilyP3Coverage
                if got==nil||got.value.ObservedAt!="2026-11-21T19:00:00Z"||
                    !got.observedAt.Equal(date){
                    t.Fatal("Coverage P5 validated payload/observation time lost")
                }
            }
        })
    }
}
func TestC1PreparedRAMFileAndCoverageCannotFallBackToReparse(t *testing.T){
    for _,kind:=range []string{"FileObservation","WindowsSecurityCoverage"}{
        raw:=[]byte("{\"version\":\"fi-spool-record/0.1\",\"record_kind\":\""+kind+"\",\"scope_id\":\"root\",\"written_at\":\"2026-11-21T19:00:00Z\",\"payload\":{}}\n")
        prepared,err:=PrepareSourceRecord(raw);if err!=nil{t.Fatal(err)}
        _,err=encodeC1PreparedRAMRows([]privateP6Record{{
            signedBatchIndex:0,sourceBatchID:42,ordinal:1,prepared:prepared,
        }})
        if err==nil{t.Fatalf("unprepared %s accepted across RAM transport",kind)}
    }
}
