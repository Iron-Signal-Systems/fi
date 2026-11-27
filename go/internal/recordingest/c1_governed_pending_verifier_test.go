//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import "testing"

// The separate B child receives only the fi-sor-selected static schema,
// never an arbitrary SQL namespace or a client-supplied query.
func TestC1GovernedPendingNativeBRequiresWhitelistedRelationalSchema(t *testing.T) {
	p := c1NativeBTestPlan()
	schema, err := c1NativeBSchema(p)
	if err != nil || schema != privateProjectionSchema {
		t.Fatalf("C1 isolated B default changed: schema=%q err=%v", schema, err)
	}
	p.SQLSchema = c1GovernedPendingSchema
	schema, err = c1NativeBSchema(p)
	if err != nil || schema != c1GovernedPendingSchema {
		t.Fatalf("C1 pending B target not selectable: schema=%q err=%v", schema, err)
	}
	if err = c1ValidateNativeBPlan(p); err != nil {
		t.Fatalf("signed group verifier rejected governed pending schema: %v", err)
	}
	p.SQLSchema = "fi"
    schema, err = c1NativeBSchema(p)
    if err != nil || schema != "fi" {
        t.Fatalf("B cannot select the explicitly approved direct canonical target: schema=%q err=%v",schema,err)
    }
    if err = c1ValidateNativeBPlan(p); err != nil {
        t.Fatalf("independent B rejected the signed direct-canonical plan: %v",err)
    }
    for _, bad := range []string{"pg_catalog", "public", "fi_c1_pending; DROP SCHEMA fi", "fi_recovery"} {
		p.SQLSchema = bad
		if _, err = c1NativeBSchema(p); err == nil {
			t.Fatalf("independent B accepted arbitrary relational schema %q", bad)
		}
		if err = c1ValidateNativeBPlan(p); err == nil {
			t.Fatalf("B child would accept untrusted schema in serialized plan %q", bad)
		}
	}
}
