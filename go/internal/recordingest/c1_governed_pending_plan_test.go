//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
	"strings"
	"testing"
)

func c1PendingExecutableSQL(sql string) string {
	var out strings.Builder
	for _, line := range strings.Split(sql, "\n") {
		if i := strings.Index(line, "--"); i >= 0 {
			line = line[:i]
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	return out.String()
}

// The generated plan must never touch populated authoritative FI tables.
// Real execution is reserved for a disposable PostgreSQL 18 acceptance test.
func TestC1GovernedPendingPlanContainsOnlyAdditiveIsolatedDDL(t *testing.T) {
	plan, err := C1GovernedPendingPlan()
	if err != nil {
		t.Fatal(err)
	}
	if len(plan) != 6 {
		t.Fatalf("expected five checksum-pinned migrations and lifecycle DDL, got %d", len(plan))
	}
	if plan[0].Name != "0001_relational.sql" ||
		plan[4].Name != "0005_usn_capture_binding.sql" ||
		plan[5].Name != "c1_governed_pending_control" {
		t.Fatal("C1 pending: unapproved source migration order")
	}
	for _, step := range plan {
		executable := c1PendingExecutableSQL(step.SQL)
		for _, forbidden := range []string{
			"fi_recovery_projection", "fi_recovery.", "CREATE TABLE fi.",
			"ALTER TABLE fi.", "INSERT INTO fi.", "DELETE FROM fi.",
			"DROP TABLE", "DROP SCHEMA", "DROP INDEX CONCURRENTLY",
			"\nBEGIN;\n", "\nCOMMIT;\n",
		} {
			if strings.Contains(executable, forbidden) {
				t.Fatalf("unsafe C1 pending SQL in %s: %q", step.Name, forbidden)
			}
		}
	}
	first := c1PendingExecutableSQL(plan[0].SQL)
	if !strings.Contains(first, "CREATE SCHEMA fi_c1_pending AUTHORIZATION fi_owner") ||
		!strings.Contains(first, "CREATE TABLE fi_c1_pending.recorded_generation") ||
		!strings.Contains(first, "CREATE TABLE fi_c1_pending.source_record") {
		t.Fatal("C1 pending: missing complete FK substrate")
	}
	if !strings.Contains(plan[4].SQL, "fi_c1_pending.usn_read_boundary") ||
		!strings.Contains(plan[3].SQL,
			"DROP INDEX fi_c1_pending.windows_security_event_field_name_idx;") {
		t.Fatal("C1 pending: USN/Security DDL drift")
	}
}

func TestC1GovernedPendingControlCannotClaimAcceptance(t *testing.T) {
	control := c1PendingExecutableSQL(c1PendingControlDDL)
	expected := []string{
		"c1_pending_exact_signed_identity_uq",
		"FOREIGN KEY (source_id, generation_id, receipt_sha256, transfer_sha256,",
		"CHECK (octet_length(receipt_sha256) = 32)",
		"CHECK (octet_length(transfer_sha256) = 32)",
		"CREATE UNIQUE INDEX fi_c1_pending_one_unretired_generation",
		"WHERE state <> 'Retired'",
		"verifier_b_receipt_sha256 = receipt_sha256",
		"REVOKE ALL ON fi_c1_pending.ingest_journal FROM fi_ingest",
		"REVOKE ALL ON fi_c1_pending.generation_control FROM fi_ingest",
		"GRANT SELECT ON fi_c1_pending.generation_control TO fi_ingest",
	}
	for _, fragment := range expected {
		if !strings.Contains(control, fragment) {
			t.Fatalf("C1 pending missing safety constraint %q", fragment)
		}
	}
	for _, forbidden := range []string{
		"'Accepted'", "INSERT INTO fi.ingest_journal",
		"GRANT UPDATE ON fi_c1_pending.generation_control",
		"GRANT INSERT ON fi_c1_pending.generation_control",
	} {
		if strings.Contains(control, forbidden) {
			t.Fatalf("C1 pending control can claim authority prematurely: %q", forbidden)
		}
	}
}
