//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

type c1PendingCopyCaptureTx struct {
	pgx.Tx
	table pgx.Identifier
}

func (c *c1PendingCopyCaptureTx) CopyFrom(_ context.Context, table pgx.Identifier,
	_ []string, _ pgx.CopyFromSource) (int64, error) {
	c.table = table
	return 1, nil
}

// C1 uses the same statically authored projectors and the same COPY path.
// The only change is which approved relational namespace owns pending rows.
func TestC1GovernedPendingProjectionRewritesOnlyQualifiedSQL(t *testing.T) {
	sql := "SELECT source_record_id FROM fi.source_record WHERE record_kind='fi.source_record' -- fi.source_batch\n"
	got, err := rewritePrivateProjectionStatementTo(sql, c1GovernedPendingSchema)
	if err != nil {
		t.Fatal(err)
	}
	expected := "SELECT source_record_id FROM fi_c1_pending.source_record WHERE record_kind='fi.source_record' -- fi.source_batch\n"
	if got != expected {
		t.Fatalf("unsafe SQL rewrite: got %q expected %q", got, expected)
	}
	old, err := rewritePrivateProjectionStatement(sql)
	if err != nil || !strings.Contains(old, "FROM fi_recovery_projection.source_record") {
		t.Fatalf("private benchmark rewrite changed: %q %v", old, err)
	}
}

func TestC1GovernedPendingProjectionRejectsUnknownOrAlreadyRewrittenSchema(t *testing.T) {
	for _, schema := range []string{"fi", "pg_catalog", "other_schema", "fi_c1_pending;DROP SCHEMA fi"} {
		if _, err := rewritePrivateProjectionStatementTo(
			"SELECT source_record_id FROM fi.source_record", schema); err == nil {
			t.Fatalf("accepted arbitrary SQL destination %q", schema)
		}
	}
	for _, sql := range []string{
		"SELECT * FROM fi_c1_pending.source_record",
		"SELECT * FROM fi_recovery_projection.source_record",
		"DELETE FROM fi.source_record",
		"SELECT * FROM fi.source_record; DROP SCHEMA fi",
		"SELECT * FROM source_record",
	} {
		if _, err := rewritePrivateProjectionStatementTo(sql, c1GovernedPendingSchema); err == nil {
			t.Fatalf("governed pending accepted untrusted projector statement %q", sql)
		}
	}
}

func TestC1GovernedPendingCopyTargetCannotEscapeApprovedNamespace(t *testing.T) {
	ctx := context.Background()
	capture := &c1PendingCopyCaptureTx{}
	p := privateProjectionTx{Tx: capture, schema: c1GovernedPendingSchema}
	n, err := p.CopyFrom(ctx, pgx.Identifier{"fi", "source_record"}, nil, nil)
	if err != nil || n != 1 || len(capture.table) != 2 ||
		capture.table[0] != c1GovernedPendingSchema || capture.table[1] != "source_record" {
		t.Fatalf("C1 COPY escaped governed pending: %v rows=%d table=%v", err, n, capture.table)
	}
	for _, bad := range []pgx.Identifier{
		{"fi_c1_pending", "source_record"}, {"fi", "source_record", "child"}, {"pg_catalog", "pg_class"},
	} {
		if _, err = p.CopyFrom(ctx, bad, nil, nil); err == nil {
			t.Fatalf("COPY accepted unapproved table %v", bad)
		}
	}
	p.fieldPartition = "windows_security_event_field_some_partition"
	if _, err = p.CopyFrom(ctx, pgx.Identifier{"fi", "windows_security_event_field"}, nil, nil); err == nil {
		t.Fatal("C1 governed pending allowed experimental partition redirection")
	}
	p.fieldPartition = ""
	p.schema = "attacker"
	if _, err = p.CopyFrom(ctx, pgx.Identifier{"fi", "source_record"}, nil, nil); err == nil {
		t.Fatal("C1 governed pending allowed arbitrary COPY schema")
	}
}

func TestC1GovernedPendingCloneUsesOriginalProjectionByDefault(t *testing.T) {
	p := privateProjectionTx{Tx: &c1PendingCopyCaptureTx{}}
	schema, err := p.destinationSchema()
	if err != nil || schema != privateProjectionSchema {
		t.Fatalf("private C1 clone redirected: schema=%q err=%v", schema, err)
	}
}
