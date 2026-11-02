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
