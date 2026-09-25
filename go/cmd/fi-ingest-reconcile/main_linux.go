// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/Iron-Signal-Systems/fi/go/internal/recordingest"
)

func main() {
	flags := flag.NewFlagSet("fi-ingest-reconcile", flag.ExitOnError)

	planMode := flags.Bool(
		"plan",
		false,
		"read immutable recorder receipts and relational PostgreSQL state without writing",
	)
	inventoryMode := flags.Bool(
		"inventory",
		false,
		"revalidate pending recorded generations through FI custody and count validated source record kinds without writing",
	)
	sourceFilter := flags.String(
		"source",
		"",
		"optional FI source ID filter; empty selects all recorded sources",
	)
	maxInspect := flags.Uint64(
		"max-inspect",
		0,
		"maximum pending generations to inspect in inventory mode; zero means no limit",
	)
	stopWhenCovered := flags.Bool(
		"stop-when-covered",
		true,
		"stop inventory after all supported record kinds are covered by authoritative plus inspected generations",
	)
	connectionString := flags.String(
		"postgres",
		recordingest.DefaultPostgreSQLConnectionString,
		"FI PostgreSQL connection string",
	)
	custodyRoot := flags.String(
		"generation-custody-root",
		"/var/lib/fi/custody/generation",
		"durable FI generation custody root",
	)
	recordedRoot := flags.String(
		"generation-recorded-root",
		"/var/lib/fi/custody/recorded",
		"durable FI generation recorder root",
	)
	maxCanonicalBytes := flags.Uint64(
		"generation-max-canonical-bytes",
		68719476736,
		"maximum canonical bytes accepted while inventory revalidates custody",
	)
	maxEncodedBytes := flags.Uint64(
		"generation-max-encoded-bytes",
		68719476736,
		"maximum encoded bytes accepted while inventory revalidates custody",
	)
	maxManifestBytes := flags.Uint64(
		"generation-max-manifest-bytes",
		1048576,
		"maximum collector manifest bytes accepted while inventory revalidates custody",
	)

	_ = flags.Parse(os.Args[1:])
	if flags.NArg() != 0 || (*planMode == *inventoryMode) {
		usage()
	}

	ctx := context.Background()
	connection, _, err := recordingest.OpenPostgreSQL(ctx, *connectionString)
	if err != nil {
		fail(err)
	}
	defer connection.Close(ctx)

	if *planMode {
		plan, err := recordingest.PlanRecordedGenerations(ctx, connection, *recordedRoot, *sourceFilter)
		if err != nil {
			fail(err)
		}
		printPlan(plan)
		return
	}

	inventory, err := recordingest.InventoryPendingRecordedGenerations(
		ctx,
		connection,
		recordingest.GenerationLoadConfig{
			CustodyRoot:       *custodyRoot,
			MaxCanonicalBytes: *maxCanonicalBytes,
			MaxEncodedBytes:   *maxEncodedBytes,
			MaxManifestBytes:  *maxManifestBytes,
			RecordedRoot:      *recordedRoot,
		},
		*sourceFilter,
		*maxInspect,
		*stopWhenCovered,
	)
	if err != nil {
		printInventory(inventory)
		fail(err)
	}
	printInventory(inventory)
}

func printPlan(plan recordingest.ReconcilePlan) {
	fmt.Printf("ReceiptsDiscovered: %d\n", plan.Discovered)
	fmt.Printf("AlreadyAccepted:    %d\n", plan.Accepted)
	fmt.Printf("Pending:            %d\n", plan.Pending)
	fmt.Printf("Conflict:           %d\n", plan.Conflict)

	for _, item := range plan.Items {
		if item.State != recordingest.ReconcileStateConflict {
			continue
		}
		fmt.Printf("ConflictCandidate:  %s %s\n", item.Candidate.SourceID, item.Candidate.GenerationID)
		if item.Detail != "" {
			fmt.Printf("Detail:             %s\n", item.Detail)
		}
	}
}

func printInventory(inventory recordingest.PendingInventory) {
	fmt.Println("===== READ-ONLY RELATIONAL COVERAGE INVENTORY =====")
	fmt.Printf("ReceiptsDiscovered: %d\n", inventory.Discovered)
	fmt.Printf("AlreadyAccepted:    %d\n", inventory.SkippedAccepted)
	fmt.Printf("Pending:            %d\n", inventory.Pending)
	fmt.Printf("Conflict:           %d\n", inventory.Conflict)
	fmt.Printf("InspectedPending:   %d\n", inventory.Inspected)
	fmt.Printf("AuthoritativeKinds: %s\n", formatKindCounts(inventory.AuthoritativeKindCounts))

	for _, item := range inventory.Items {
		fmt.Println()
		fmt.Printf("Source:             %s\n", item.Candidate.SourceID)
		fmt.Printf("GenerationID:       %s\n", item.Candidate.GenerationID)
		fmt.Printf("Records:            %d\n", item.Records)
		fmt.Printf("DataBytes:          %d\n", item.DataBytes)
		fmt.Printf("RecordKinds:        %s\n", formatKindCounts(item.KindCounts))
	}

	fmt.Println()
	covered := len(recordingest.SupportedRecordKinds()) - len(inventory.MissingKinds)
	fmt.Printf("CoverageKinds:      %d/%d\n", covered, len(recordingest.SupportedRecordKinds()))
	if len(inventory.MissingKinds) == 0 {
		fmt.Println("MissingKinds:       NONE")
	} else {
		fmt.Printf("MissingKinds:       %s\n", strings.Join(inventory.MissingKinds, ","))
	}
	fmt.Println("DatabaseWrites:     0")
}

func formatKindCounts(counts []recordingest.RecordKindCount) string {
	if len(counts) == 0 {
		return "NONE"
	}
	parts := make([]string, 0, len(counts))
	for _, item := range counts {
		parts = append(parts, fmt.Sprintf("%s=%d", item.Kind, item.Count))
	}
	return strings.Join(parts, ",")
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "ERROR:", err)
	os.Exit(1)
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  fi-ingest-reconcile -plan [-source <source-id>]")
	fmt.Fprintln(os.Stderr, "  fi-ingest-reconcile -inventory [-source <source-id>] [-max-inspect <n>] [-stop-when-covered=true|false]")
	os.Exit(2)
}
