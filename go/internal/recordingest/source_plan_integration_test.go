// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/generationrecorder"
)

func TestM1SourcePlanPostgreSQLFailureBoundaries(t *testing.T) {
	base := os.Getenv("FI_M1_TEST_POSTGRES_ROOT")
	if base == "" {
		t.Skip("isolated PostgreSQL fixture not requested")
	}

	expected := filepath.Join(
		os.Getenv("HOME"),
		"fi-m1-postgres-20261012",
	)
	if base != expected {
		t.Fatalf("unexpected PostgreSQL fixture %q", base)
	}

	version, err := os.ReadFile(
		filepath.Join(base, "data", "PG_VERSION"),
	)
	if err != nil || strings.TrimSpace(string(version)) != "18" {
		t.Fatal("PostgreSQL 18 fixture not verified")
	}

	ctx, cancel := context.WithTimeout(
		context.Background(),
		30*time.Second,
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
		t.Fatalf("unexpected table count: %d", state.RelationalTables)
	}

	const (
		fs19 = "iss-fs-2019.iss.local"
		fs22 = "iss-fs-22.iss.local"
	)

	root := t.TempDir()
	sources := filepath.Join(root, "sources")

	if err := os.Mkdir(sources, 0700); err != nil {
		t.Fatal(err)
	}

	for _, source := range []string{fs19, fs22} {
		directory := filepath.Join(sources, source)

		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}

		raw := strings.Replace(
			reconcileTestReceipt,
			`"source_id":"iss-fs-01.iss.local"`,
			`"source_id":"`+source+`"`,
			1,
		)

		receipt, err :=
			generationrecorder.UnmarshalRecordedReceipt([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}

		name := generationrecorder.RecordedReceiptObjectName(
			source,
			receipt.Descriptor.GenerationID,
		)

		if err := os.WriteFile(
			filepath.Join(directory, name),
			[]byte(raw),
			0400,
		); err != nil {
			t.Fatal(err)
		}
	}

	checkPending := func(source string) {
		t.Helper()

		plan, err := PlanRecordedGenerationsForSource(
			ctx,
			db,
			root,
			source,
		)
		if err != nil {
			t.Fatal(err)
		}

		if plan.Discovered != 1 ||
			plan.Pending != 1 ||
			plan.Accepted != 0 ||
			plan.Conflict != 0 {
			t.Fatalf(
				"unexpected source %s plan: %+v",
				source,
				plan,
			)
		}
	}

	checkPending(fs19)
	checkPending(fs22)

	corrupt := filepath.Join(
		sources,
		fs19,
		"generation-"+strings.Repeat("0", 64)+".record.json",
	)

	if err := os.WriteFile(
		corrupt,
		[]byte("{invalid-receipt"),
		0400,
	); err != nil {
		t.Fatal(err)
	}

	_, err = PlanRecordedGenerationsForSource(
		ctx,
		db,
		root,
		fs19,
	)

	var discovery *SourceReceiptDiscoveryError

	if !errors.As(err, &discovery) {
		t.Fatalf(
			"malformed FS2019 receipt lacks source attribution: %v",
			err,
		)
	}

	if discovery.SourceID != fs19 {
		t.Fatalf(
			"discovery failure attributed to %q",
			discovery.SourceID,
		)
	}

	t.Log("PASS: Malformed receipt classified as FS2019 discovery failure")

	checkPending(fs22)

	t.Log("PASS: FS22 PostgreSQL reconciliation remained operational")

	if err := os.Remove(corrupt); err != nil {
		t.Fatal(err)
	}

	checkPending(fs19)

	t.Log("PASS: FS2019 receipt discovery recovered after correction")

	if err := db.Close(ctx); err != nil {
		t.Fatal(err)
	}

	_, err = PlanRecordedGenerationsForSource(
		ctx,
		db,
		root,
		fs22,
	)

	if err == nil {
		t.Fatal("closed PostgreSQL connection was accepted")
	}

	discovery = nil

	if errors.As(err, &discovery) {
		t.Fatalf(
			"PostgreSQL failure incorrectly classified as source-local: %v",
			err,
		)
	}

	t.Log("PASS: PostgreSQL failure remained global")
}
