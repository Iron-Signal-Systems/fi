//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
	"context"
	"strings"
	"testing"
)

func TestC1PendingRetirementOnlyTouchesFrozenPendingRelationalTables(t *testing.T) {
	names, err := c1PendingRetireTables()
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 52 {
		t.Fatalf("C1 pending must retire exactly 51 relations + one control, got %d",len(names))
	}
	seen := map[string]bool{}
	for _, name := range names {
		if !strings.HasPrefix(name, "\"fi_c1_pending\".") ||
			strings.Contains(name, "fi_recovery") ||
			strings.Contains(name, "\"fi\".") ||
			seen[name] {
			t.Fatalf("C1 pending retirement could touch canonical or duplicate table %q",name)
		}
		seen[name] = true
	}
	if !seen["\"fi_c1_pending\".\"generation_control\""] ||
		!seen["\"fi_c1_pending\".\"windows_security_event_field\""] ||
		!seen["\"fi_c1_pending\".\"source_record\""] ||
        !seen["\"fi_c1_pending\".\"usn_scoped_capture\""] ||
        !seen["\"fi_c1_pending\".\"usn_scoped_change\""] {
		t.Fatal("C1 retirement omitted the control, SourceParent or Security child rows")
	}
}

func TestC1PendingRetirementFailsBeforeConnectingOnUntrustedIdentity(t *testing.T) {
	for _, input := range []struct{source,generation,receipt string}{
		{"","gen",strings.Repeat("a",64)},
		{"source","",strings.Repeat("a",64)},
		{"source","gen","wrong"},
		{"source","gen",strings.Repeat("x",64)},
	} {
		if err:=C1RetireAcceptedPending(context.Background(),"",
			input.source,input.generation,input.receipt);err==nil{
			t.Fatalf("C1 retirement accepted unsigned identity %+v",input)
		}
	}
	if err:=C1RetireAcceptedPending(nil,"","s","g",strings.Repeat("a",64));err==nil{
		t.Fatal("C1 pending retirement accepted nil context")
	}
}
