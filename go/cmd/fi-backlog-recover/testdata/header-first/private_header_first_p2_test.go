// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
    "bufio"
    "bytes"
    "context"
    "crypto/sha256"
    "errors"
    "fmt"
    "strings"
    "testing"
)

func TestPrivateHeaderFirstP2PreservesOrdinalsAndExactBytes(t *testing.T) {
    const n = 600
    kinds := []string{"WindowsSecurityEvent", "FileObservation", "WindowsSecurityCoverage",
        "USNReadBoundary", "USNObjectObservation", "CollectorIdentity"}
    var streamData []byte
    expected := make([][]byte, n)
    for i := 0; i < n; i++ {
        expected[i] = canonicalDispatchFixture(kinds[i%len(kinds)], fmt.Sprintf("{\"i\":%d}", i))
        streamData = append(streamData, expected[i]...)
    }
    prepare := func(raw []byte, kind string, family spoolDispatchFamily) (SourceRecord, securityBulkRecord, bool, error) {
        if len(raw) == 0 || !bytes.Contains(raw[:min(128,len(raw))], []byte(kind)) {
            return SourceRecord{}, securityBulkRecord{}, false, errors.New("header-first dispatch lost kind")
        }
        return SourceRecord{RecordDigest: sha256.Sum256(raw)}, securityBulkRecord{}, false, nil
    }
    got, err := newPrivateHeaderFirstPreparedStream(context.Background(),
        bufio.NewReader(bytes.NewReader(streamData)), prepare)
    if err != nil { t.Fatal(err) }
    defer got.Close()
    original := sha256.New()
    for i := range expected {
        row, ok := got.Next()
        if !ok || row.readErr != nil || row.prepareErr != nil {
            t.Fatalf("row=%d ok=%t read=%v prepare=%v",i,ok,row.readErr,row.prepareErr)
        }
        if row.ordinal != int64(i+1) || !bytes.Equal(row.raw,expected[i]) ||
            row.headerKind != kinds[i%len(kinds)] ||
            row.source.RecordDigest != sha256.Sum256(expected[i]) {
            t.Fatalf("signed source/dispatch changed row=%d",i)
        }
        _,_ = original.Write(row.raw)
    }
    if _,ok:=got.Next(); ok {t.Fatal("unexpected record after EOF")}
    whole := sha256.Sum256(streamData)
    if !bytes.Equal(original.Sum(nil),whole[:]) {t.Fatal("signed byte stream changed")}
    if got.rows != n {t.Fatalf("rows=%d",got.rows)}
}

func TestPrivateHeaderFirstP2FailsClosedOnMissingLF(t *testing.T) {
    one := canonicalDispatchFixture("WindowsSecurityEvent","{}")
    bad := bytes.TrimSuffix(canonicalDispatchFixture("FileObservation","{}"),[]byte("\n"))
    data := append(bytes.Clone(one),bad...)
    s,err:=newPrivateHeaderFirstPreparedStream(context.Background(),
        bufio.NewReader(bytes.NewReader(data)),
        func(raw []byte, kind string, family spoolDispatchFamily)(SourceRecord,securityBulkRecord,bool,error){
            return SourceRecord{},securityBulkRecord{},false,nil
        })
    if err!=nil {t.Fatal(err)}
    defer s.Close()
    row,ok:=s.Next()
    if !ok || row.readErr!=nil || row.ordinal!=1 {t.Fatalf("first row: %+v",row)}
    row,ok=s.Next()
    if !ok || row.readErr==nil || row.ordinal!=2 {t.Fatalf("missing final LF not rejected: %+v",row)}
}

func TestPrivateHeaderFirstP2RejectsInvalidRecordKind(t *testing.T) {
    a:=canonicalDispatchFixture("CollectorIdentity","{}")
    b:=canonicalDispatchFixture("UnsupportedSourceKind","{}")
    data:=append(bytes.Clone(a),b...)
    s,err:=newPrivateHeaderFirstPreparedStream(context.Background(),
        bufio.NewReader(bytes.NewReader(data)),
        func(raw []byte, kind string, family spoolDispatchFamily)(SourceRecord,securityBulkRecord,bool,error){
            return SourceRecord{},securityBulkRecord,false,nil
        })
    if err!=nil {t.Fatal(err)}
    defer s.Close()
    if row,ok:=s.Next();!ok||row.readErr!=nil {t.Fatalf("first row: %+v",row)}
    if row,ok:=s.Next();!ok||row.readErr==nil {t.Fatalf("unknown kind not rejected: %+v",row)}
}

func TestPrivateHeaderFirstP2CloseOnCancellation(t *testing.T) {
    raw:=canonicalDispatchFixture("WindowsSecurityEvent","{}")
    ctx,cancel:=context.WithCancel(context.Background())
    var data []byte
    for i:=0;i<1000;i++ {data=append(data,raw...)}
    s,err:=newPrivateHeaderFirstPreparedStream(ctx,bufio.NewReader(bytes.NewReader(data)),
        func(raw []byte,kind string,family spoolDispatchFamily)(SourceRecord,securityBulkRecord,bool,error){
            return SourceRecord{},securityBulkRecord{},false,nil
        })
    if err!=nil {t.Fatal(err)}
    _,_ = s.Next()
    cancel()
    s.Close()
}

func TestPrivateHeaderFirstP2RejectsNilInputs(t *testing.T) {
    _,err:=newPrivateHeaderFirstPreparedStream(context.Background(),nil,
        func([]byte,string,spoolDispatchFamily)(SourceRecord,securityBulkRecord,bool,error){
            return SourceRecord{},securityBulkRecord{},false,nil
        })
    if err==nil {t.Fatal("nil reader accepted")}
    _,err=newPrivateHeaderFirstPreparedStream(context.Background(),bufio.NewReader(strings.NewReader("")),
        nil)
    if err==nil {t.Fatal("nil processor accepted")}
}
