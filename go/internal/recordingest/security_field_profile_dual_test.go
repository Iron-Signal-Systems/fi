package recordingest

import (
	"context"
	"testing"
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
    scopeFixture:=securityScopeCandidateFixture()
    if _,ok:=securityScopeCopyRows(candidate,scopeFixture,3).(*securityScopeCopySource);!ok{
        t.Fatal("C1 candidate did not select existing reusable 4-column scope COPY source")
    }
    if _,ok:=securityScopeCopyRows(control,scopeFixture,3).(*securityScopeCopySource);ok{
        t.Fatal("non-C1 P4 unexpectedly selected reusable scope COPY source")
    }
    if securityScopeCopyRows(candidate,scopeFixture,0)!=nil{
        t.Fatal("zero matched scopes unexpectedly generated a COPY")
    }
}
