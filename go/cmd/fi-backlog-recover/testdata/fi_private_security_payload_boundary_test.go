// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Tests belong to the disposable historical source, not the live FI build.
package recordingest

import (
    "bytes"
    "encoding/json"
    "math/rand"
    "strings"
    "testing"
)

// The original fast-path selection gate used independently verified JSON
// values. Preserve its true/false decision for all malformed and unusual
// signed envelopes while skipping the redundant validation for canonical
// Security payloads when the strict decoder succeeds.
func originalSinglePassSecuritySelection(raw []byte) bool {
    if len(raw)<len(securityEnvelopePrefix)+len(securityPayloadKey)+2 ||
       !bytes.HasPrefix(raw,securityEnvelopePrefix) ||
       raw[len(raw)-1]!='\n' || raw[len(raw)-2]!='}' {
        return false
    }
    body:=raw[:len(raw)-1]
    if bytes.Contains(body,[]byte{'\n'}) {return false}
    written,payload,unique:=findSinglePassSecurityEnvelopeKeys(body)
    if !unique || written<=len(securityEnvelopePrefix) ||
       payload<=written+len(securityWrittenAtKey) {
        return false
    }
    scope:=body[len(securityEnvelopePrefix):written]
    writtenAt:=body[written+len(securityWrittenAtKey):payload]
    if len(scope)<2 || scope[0]!='"' || scope[len(scope)-1]!='"' ||
       !json.Valid(scope) ||
       len(writtenAt)<2 || writtenAt[0]!='"' || writtenAt[len(writtenAt)-1]!='"' ||
       !json.Valid(writtenAt) {
        return false
    }
    rawPayload:=body[payload+len(securityPayloadKey):len(body)-1]
    return len(rawPayload)>0 && json.Valid(rawPayload)
}

func TestPrivateSecurityPayloadBoundaryAcceptedJSON(t *testing.T) {
    valid:=[]string{
        `{}`,
        `{"event_id":"4663","fields":[{"name":"A","value":"B"}]}`,
        `{"one":{"two":[{"quoted":"\\\"} {} [ \\\""},{"y":true}]}}`,
        `{"raw_xml":"<Event>\\\" { [ ] } \\\"</Event>","fields":[{"name":"A","value":"B"}]}`,
    }
    for _,x:=range valid {
        if !json.Valid([]byte(x)) {t.Fatalf("invalid test literal: %s",x)}
        if !privateSingleJSONObjectBoundary([]byte(x)) {t.Fatalf("rejected valid object: %s",x)}
    }
    for _,x:=range []string{
        `{}`+`,"version":"another"`,
        `{"fields":[]}{}`,
        `{"fields":[1,2}}`,
        `{"quoted":"unfinished}`,
        `[{"value":1}]`,
    } {
        if privateSingleJSONObjectBoundary([]byte(x)) {t.Errorf("accepted non-canonical span: %s",x)}
    }
}

func TestPrivateSecurityPayloadBoundarySelectionEquivalent(t *testing.T) {
    baseline:=singlePassSecurityTestRecord(t,32,16384)
    if !originalSinglePassSecuritySelection(baseline) {t.Fatal("baseline unexpectedly not canonical")}
    if _,_,selected,err:=tryPrepareSinglePassSecurity(baseline);err!=nil||!selected {
        t.Fatalf("new canonical selection=%t err=%v",selected,err)
    }
    variants:=[][]byte{
        bytes.Replace(baseline,[]byte(`"event_id":"4663"`),[]byte(`"event_id":false`),1),
        bytes.Replace(baseline,[]byte(`"scope_id":"test-scope"`),[]byte(`"scope_id":false`),1),
        bytes.Replace(baseline,[]byte(`"fields":[`),[]byte(`"fields": [`),1),
        bytes.Replace(baseline,[]byte(`"event_id":"4663"`),[]byte(`"event_id":"\\q"`),1),
        bytes.Replace(baseline,[]byte(`"event_id":"4663"`),[]byte(`"event_id":[}}`),1),
        baseline[:len(baseline)-1],
    }
    trailing:=append([]byte(nil),baseline[:len(baseline)-2]...)
    trailing=append(trailing,[]byte(`,"version":"fi-spool-record/0.1"}`)...)
    variants=append(variants,append(trailing,'\n'))
    seeded:=rand.New(rand.NewSource(20261111))
    for i:=0;i<12000;i++{
        mutated:=append([]byte(nil),baseline...)
        // Probe commas, braces, UTF-8, quote/backslash, and invalid bytes
        // throughout the envelope (including the copied XML).
        for j:=0;j<1+i%3;j++{
            position:=seeded.Intn(len(mutated))
            mutated[position]=byte(seeded.Intn(256))
        }
        variants=append(variants,mutated)
    }
    for i,raw:=range variants {
        expected:=originalSinglePassSecuritySelection(raw)
        _,_,selected,_:=tryPrepareSinglePassSecurity(raw)
        if selected!=expected {
            t.Fatalf("selection differs at case %d: original=%t candidate=%t len=%d",i,expected,selected,len(raw))
        }
    }
}

var privateSecurityPayloadProbeSink bool

func BenchmarkPrivateSecurityPayloadBoundary(b *testing.B) {
    // Actual canonical envelope fixture, with enough XML to exercise large
    // Security event payloads. This is a Go-only microbenchmark, not SQL time.
    raw:=singlePassSecurityTestRecord(b,32,16384)
    idx:=bytes.Index(raw,securityPayloadKey)
    if idx<0 {b.Fatal("payload key not found")}
    payload:=raw[idx+len(securityPayloadKey):len(raw)-2]
    if !json.Valid(payload) {b.Fatal("fixture invalid")}
    b.Run("previous-json-valid",func(b *testing.B) {
        b.ReportAllocs()
        for i:=0;i<b.N;i++{privateSecurityPayloadProbeSink=json.Valid(payload)}
    })
    b.Run("bounded-object-scan",func(b *testing.B) {
        b.ReportAllocs()
        for i:=0;i<b.N;i++{privateSecurityPayloadProbeSink=privateSingleJSONObjectBoundary(payload)}
    })
    _=strings.Builder{}
}
