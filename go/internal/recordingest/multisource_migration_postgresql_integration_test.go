// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestM1MigrationPostgreSQLParity238(t *testing.T) {
	base := os.Getenv("FI_M1_TEST_POSTGRES_ROOT")
	if base == "" ||
		os.Getenv("FI_M1_NAMESPACE_READ_TEST") != "1" {
		t.Skip("isolated M1 integration test not enabled")
	}

	expected := filepath.Join(
		os.Getenv("HOME"),
		"fi-m1-postgres-20261012",
	)
	if base != expected {
		t.Fatalf("unexpected PostgreSQL root %q", base)
	}

	version, err := os.ReadFile(
		filepath.Join(base, "data", "PG_VERSION"),
	)
	if err != nil || string(version) != "18\n" {
		t.Fatal("isolated PostgreSQL version check failed")
	}

	fixture := filepath.Join(
		os.Getenv("HOME"),
		"fi-m1-receipts-20261012",
	)

	flat := filepath.Join(fixture, "flat")
	named := filepath.Join(fixture, "namespaced")

	sources := []struct {
		id   string
		want uint64
	}{
		{"iss-fs-2019.iss.local", 104},
		{"iss-fs-22.iss.local", 134},
	}

	audit, err := AuditRecordedReceiptMigration(
		flat,
		named,
		[]string{sources[0].id, sources[1].id},
	)
	if err != nil {
		t.Fatal(err)
	}
	if audit.Legacy != 238 || audit.Namespaced != 238 {
		t.Fatalf("migration accounting changed: %+v", audit)
	}

	ctx, cancel := context.WithTimeout(
		context.Background(),
		60*time.Second,
	)
	defer cancel()

	connectionString := fmt.Sprintf(
		"host=%s port=55418 user=fi_ingest dbname=fi sslmode=disable connect_timeout=3",
		filepath.Join(base, "socket"),
	)

	db, state, err := OpenPostgreSQL(ctx, connectionString)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close(context.Background())

	if state.RelationalTables != 49 {
		t.Fatalf(
			"unexpected relational schema: %d tables",
			state.RelationalTables,
		)
	}

	var total uint64

	for _, source := range sources {
		flatPlan, err := PlanRecordedGenerationsForIngest(
			ctx,
			db,
			flat,
			source.id,
		)
		if err != nil {
			t.Fatalf("flat %s: %v", source.id, err)
		}

		namedPlan, err := PlanRecordedGenerationsForSource(
			ctx,
			db,
			named,
			source.id,
		)
		if err != nil {
			t.Fatalf("namespaced %s: %v", source.id, err)
		}

		for _, plan := range []ReconcilePlan{
			flatPlan,
			namedPlan,
		} {
			if plan.Discovered != source.want ||
				plan.Pending != source.want ||
				plan.Accepted != 0 ||
				plan.Conflict != 0 ||
				uint64(len(plan.Items)) != source.want {
				t.Fatalf(
					"unexpected reconciliation for %s: %+v",
					source.id,
					plan,
				)
			}
		}

		original := make(
			map[string]ReconcilePlanItem,
			len(flatPlan.Items),
		)

		for _, item := range flatPlan.Items {
			id := item.Candidate.GenerationID

			if _, exists := original[id]; exists {
				t.Fatalf(
					"duplicate flat generation %s/%s",
					source.id, id,
				)
			}

			original[id] = item
		}

		matched := make(map[string]bool)

		for _, item := range namedPlan.Items {
			id := item.Candidate.GenerationID

			previous, exists := original[id]
			if !exists || matched[id] {
				t.Fatalf(
					"unexpected or repeated generation %s/%s",
					source.id, id,
				)
			}
			matched[id] = true

			expectedPath := filepath.Join(
				named,
				"sources",
				source.id,
				filepath.Base(previous.Candidate.Path),
			)

			if item.Candidate.Path != expectedPath {
				t.Fatalf(
					"incorrect namespaced receipt path: %q",
					item.Candidate.Path,
				)
			}

			// Path is the only permitted difference between
			// the legacy and namespaced relational plans.
			previous.Candidate.Path = ""
			item.Candidate.Path = ""

			if previous != item {
				t.Fatalf(
					"relational plan changed for %s/%s",
					source.id, id,
				)
			}
		}

		if len(matched) != len(original) {
			t.Fatal("namespaced plan omitted legacy generations")
		}

		total += namedPlan.Discovered

		t.Logf(
			"PASS: %s legacy=%d namespaced=%d pending=%d conflicts=%d",
			source.id,
			flatPlan.Discovered,
			namedPlan.Discovered,
			namedPlan.Pending,
			namedPlan.Conflict,
		)
	}

	if total != 238 {
		t.Fatalf("total reconciled=%d, want 238", total)
	}

	t.Log("PASS: All 238 receipt identities and relational decisions agree")
}
