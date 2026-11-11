// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Private pinned H16 Security JSON-once candidate acceptance checks.
package recordingest

import (
    "bytes"
    "encoding/json"
    "math/rand"
    "reflect"
    "testing"
)

// The prior canonical fast-path selected only records whose payload slice
// passed a SECOND complete json.Valid traversal.
func legacySecurityPayloadSelection(raw []byte) bool {
    if len(raw)<len(securityEnvelopePrefix)+len(securityPayloadKey)+2 ||
        !bytes.HasPrefix(raw,securityEnvelopePrefix) ||
        raw[len(raw)-1]!='\n'||raw[len(raw)-2]!='}' {return false}
    body:=raw[:len(raw)-1]
    if bytes.Contains(body,[]byte{'\n'}) {return false}
    written,payload,unique:=findSinglePassSecurityEnvelopeKeys(body)
    if !unique||written<=len(securityEnvelopePrefix)||
        payload<=written+len(securityWrittenAtKey) {return false}
    scope:=body[len(securityEnvelopePrefix):written]
    writtenAt:=body[written+len(securityWrittenAtKey):payload]
    if len(scope)<2||scope[0]!='"'||scope[len(scope)-1]!='"'||!json.Valid(scope)||
        len(writtenAt)<2||writtenAt[0]!='"'||
        writtenAt[len(writtenAt)-1]!='"'||!json.Valid(writtenAt) {return false}
    bodyPayload:=body[payload+len(securityPayloadKey):len(body)-1]
    return len(bodyPayload)>0 && json.Valid(bodyPayload)
}

func TestPrivateSecurityJSONOnceSelectionParity(t *testing.T) {
    original:=singlePassSecurityTestRecord(t,24,8192)
    if !legacySecurityPayloadSelection(original){t.Fatal("input is not canonical")}
    src,record,selected,err:=tryPrepareSinglePassSecurity(original)
    if err!=nil||!selected {t.Fatalf("canonical selected=%t err=%v",selected,err)}
    old,err:=prepareOwnedSourceRecord(original)
    if err!=nil {t.Fatal(err)}
    oldSecurity,err:=prepareSecurityBulkRecord(1,old,old.RecordDigest[:])
    if err!=nil {t.Fatal(err)}
    if !reflect.DeepEqual(src,old)||!reflect.DeepEqual(record.value,oldSecurity.value) {
        t.Fatal("signed source, digest, or Security typed projection changed")
    }
    variants:=[][]byte{
        bytes.Replace(original,[]byte("\"event_id\":\"4663\""),[]byte("\"event_id\":false"),1),
        bytes.Replace(original,[]byte("\"scope_id\":\"test-scope\""),[]byte("\"scope_id\":false"),1),
        bytes.Replace(original,[]byte("\"event_id\":\"4663\""),[]byte("\"event_id\":\"\\q\""),1),
        bytes.Replace(original,[]byte("\"event_id\":\"4663\""),[]byte("\"event_id\":[}}"),1),
        original[:len(original)-1],
    }
    for _,extra:=range []string{
        ",\"version\":\"fi-spool-record/0.1\"}",
        ",\"Payload\":{}}",
        ",\"payload\" : {}}",
        ",\"unknown\":{\"x\":1}}",
        ",\"record_kind\":\"WindowsSecurityEvent\"}",
    } {
        b:=append([]byte(nil),original[:len(original)-2]...)
        b=append(b,[]byte(extra)...)
        variants=append(variants,append(b,'\n'))
    }
    rng:=rand.New(rand.NewSource(20261111))
    for i:=0;i<12000;i++{
        b:=append([]byte(nil),original...)
        for j:=0;j<1+i%3;j++ {
            b[rng.Intn(len(b))]=byte(rng.Intn(256))
        }
        variants=append(variants,b)
    }
    for i,raw:=range variants {
        expected:=legacySecurityPayloadSelection(raw)
        _,_,selected,_:=tryPrepareSinglePassSecurity(raw)
        if expected!=selected {
            t.Fatalf("legacy selection differs case=%d want=%t got=%t length=%d",
                i,expected,selected,len(raw))
        }
    }
}

var privateJSONOnceBenchmarkBytes int

func BenchmarkPrivateSecurityJSONOnceEndToEnd(b *testing.B) {
    raw:=singlePassSecurityTestRecord(b,24,8192)
    b.ReportAllocs()
    for i:=0;i<b.N;i++{
        source,security,selected,err:=tryPrepareSinglePassSecurity(raw)
        if err!=nil||!selected {b.Fatalf("selection=%t err=%v",selected,err)}
        privateJSONOnceBenchmarkBytes=source.RecordBytes+len(security.value.Fields)
    }
}
