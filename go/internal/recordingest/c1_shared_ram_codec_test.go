//go:build fi_c1_sor_dev
package recordingest

import (
    "bytes"
    "crypto/sha256"
    "strings"
    "testing"
    "time"

    "github.com/Iron-Signal-Systems/fi/go/internal/spool"
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
    _=time.Second
    _=spool.Record{}
}
