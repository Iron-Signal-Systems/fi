package recordingest

import (
	"context"
	"testing"
    "strings"
    "reflect"

    "github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func TestDualSecurityFieldCopyP3Limits(t *testing.T) {
	if got := securityFieldCopyRowsForContext(context.Background()); got != securityFieldCopyMaxRows {
		t.Fatalf("default rows=%d", got)
	}
	if got := securityFieldCopyBytesForContext(context.Background()); got != securityFieldCopyMaxBytes {
		t.Fatalf("default bytes=%d", got)
	}
	ctx, err := withFixedSecurityBulkProfile(context.Background(), "P3")
	if err != nil {
		t.Fatal(err)
	}
	if got := securityFieldCopyRowsForContext(ctx); got != 32768 {
		t.Fatalf("P3 rows=%d", got)
	}
	if got := securityFieldCopyBytesForContext(ctx); got != 8<<20 {
		t.Fatalf("P3 bytes=%d", got)
	}
	p2, err := withFixedSecurityBulkProfile(context.Background(), "P2")
	if err != nil {
		t.Fatal(err)
	}
	if got := securityFieldCopyRowsForContext(p2); got != securityFieldCopyMaxRows {
		t.Fatalf("P2 rows=%d", got)
	}
}

func TestC1Security8GiBProfileSeparatesCopyFromFieldPartitioning(t *testing.T) {
    p4,err:=withFixedSecurityBulkProfile(context.Background(),"P4")
    if err!=nil{t.Fatal(err)}
    control:=p4
    candidate:=withC1SecurityCOPYExperiment(p4)
    if securityC1COPYExperimentEnabled(control)||!securityC1COPYExperimentEnabled(candidate){
        t.Fatal("C1 Security COPY switch not isolated")
    }
    if privateSecurityFieldPartitionsEnabled(candidate) || usePrivateSinglePassSecurity(candidate) {
        t.Fatal("C1 Security COPY switch unexpectedly enabled detached partitions or Security decoding")
    }
    if securityFieldCopyRowsForContext(candidate)!=65536 ||
        securityFieldCopyBytesForContext(candidate)!=16<<20 {
        t.Fatal("C1 candidate did not select 65536/16MiB child COPY")
    }
    if securityFieldCopyRowsForContext(control)!=securityFieldCopyMaxRows ||
        securityFieldCopyBytesForContext(control)!=securityFieldCopyMaxBytes {
        t.Fatal("ordinary P4 changed without private C1 switch")
    }
    p3,err:=withFixedSecurityBulkProfile(context.Background(),"P3")
    if err!=nil{t.Fatal(err)}
    if securityFieldCopyRowsForContext(p3)!=32768||
        securityFieldCopyBytesForContext(p3)!=8<<20 {
        t.Fatal("P3 established 32768/8MiB Security child COPY changed")
    }
    if _,ok:=securityEventCopyRows(candidate,candidateSecurityEventFixture(2)).(*securityEventCopySource);!ok{
        t.Fatal("C1 candidate did not select existing reusable 40-column event COPY source")
    }
    if _,ok:=securityEventCopyRows(control,candidateSecurityEventFixture(2)).(*securityEventCopySource);ok{
        t.Fatal("non-C1 P4 unexpectedly selected reusable event COPY source")
    }
    // The private C220 overlay retains the audited, existing scope
    // selection branch. Verify the exact reusable iterator against the
    // original scope row data without a second helper implementation.
    scopeFixture:=securityScopeCandidateFixture()
    scopeRows:=legacySecurityScopeValues(scopeFixture)
    source:=newSecurityScopeCopySource(scopeFixture)
    i:=0
    for source.Next(){
        got,e:=source.Values()
        if e!=nil{t.Fatal(e)}
        if i>=len(scopeRows)||!reflect.DeepEqual(got,scopeRows[i]){
            t.Fatalf("C1 Security scope row %d differs from established source",i)
        }
        i++
    }
    if i!=len(scopeRows)||source.Err()!=nil{
        t.Fatal("C1 Security scope iterator lost a signed scope row")
    }
}

func TestC1Security8GiBFieldCopyChunkBoundedAt65536Rows(t *testing.T){
    ctx,err:=withFixedSecurityBulkProfile(context.Background(),"P4")
    if err!=nil{t.Fatal(err)}
    ctx=withC1SecurityCOPYExperiment(ctx)
    fields:=make([]records.WindowsSecurityEventField,65537)
    for i:=range fields{fields[i]=records.WindowsSecurityEventField{Name:"k",Value:"v"}}
    pending:=[]securityBulkRecord{{
        sourceRecordID:9001,
        value:records.WindowsSecurityEventObservation{Fields:fields},
    }}
    cursor:=newSecurityFieldCopyCursor(pending)
    first:=&securityFieldCopyChunk{
        cursor:cursor,maxRows:securityFieldCopyRowsForContext(ctx),
        maxBytes:securityFieldCopyBytesForContext(ctx),
    }
    for first.Next(){
        v,e:=first.Values()
        if e!=nil{t.Fatal(e)}
        if v[0]!=int64(9001)||v[1]!=first.rows||v[2]!="k"||v[3]!="v"{
            t.Fatalf("field COPY row %d changed source FK, ordinal or value",first.rows)
        }
    }
    if first.rows!=65536||first.oversized{
        t.Fatalf("first candidate field COPY should contain exactly 65536 rows: rows=%d oversize=%v",first.rows,first.oversized)
    }
    second:=&securityFieldCopyChunk{
        cursor:cursor,maxRows:securityFieldCopyRowsForContext(ctx),
        maxBytes:securityFieldCopyBytesForContext(ctx),
    }
    if !second.Next(){t.Fatal("candidate dropped final child row")}
    v,err:=second.Values()
    if err!=nil{t.Fatal(err)}
    if v[1]!=65537 || second.rows!=1 || second.Next() || cursor.hasNext(){
        t.Fatal("candidate child COPY lost/reordered final field or exceeded bound")
    }
}

func TestC1Security8GiBFieldCopyByteBoundAndOversizeRecord(t *testing.T){
    ctx,err:=withFixedSecurityBulkProfile(context.Background(),"P4")
    if err!=nil{t.Fatal(err)}
    ctx=withC1SecurityCOPYExperiment(ctx)
    bigValue:=strings.Repeat("x",9<<20)
    pending:=[]securityBulkRecord{{
        sourceRecordID:8080,
        value:records.WindowsSecurityEventObservation{Fields:[]records.WindowsSecurityEventField{
            {Name:"first",Value:bigValue},
            {Name:"second",Value:bigValue},
        }},
    }}
    cursor:=newSecurityFieldCopyCursor(pending)
    first:=&securityFieldCopyChunk{cursor:cursor,
        maxRows:securityFieldCopyRowsForContext(ctx),
        maxBytes:securityFieldCopyBytesForContext(ctx)}
    if !first.Next() || first.rows!=1 || first.Next() || first.oversized {
        t.Fatal("two 9MiB fields must not share a 16MiB COPY")
    }
    second:=&securityFieldCopyChunk{cursor:cursor,
        maxRows:securityFieldCopyRowsForContext(ctx),
        maxBytes:securityFieldCopyBytesForContext(ctx)}
    if !second.Next()||second.rows!=1||second.Next()||cursor.hasNext(){
        t.Fatal("field-copy byte cap discarded or combined a boundary row")
    }
    oversized:=[]securityBulkRecord{{
        sourceRecordID:8081,
        value:records.WindowsSecurityEventObservation{Fields:[]records.WindowsSecurityEventField{
            {Name:"huge",Value:strings.Repeat("y",17<<20)},
        }},
    }}
    larger:=newSecurityFieldCopyCursor(oversized)
    chunk:=&securityFieldCopyChunk{cursor:larger,
        maxRows:securityFieldCopyRowsForContext(ctx),
        maxBytes:securityFieldCopyBytesForContext(ctx)}
    if !chunk.Next()||chunk.rows!=1||!chunk.oversized||chunk.Next(){
        t.Fatal("single oversized valid Security field was not isolated intact")
    }
}
