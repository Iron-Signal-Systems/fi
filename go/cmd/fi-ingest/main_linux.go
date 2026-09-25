// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/Iron-Signal-Systems/fi/go/internal/recordingest"
)

func main() {
	flags := flag.NewFlagSet("fi-ingest", flag.ExitOnError)
	databaseCheck := flags.Bool("database-check", false, "verify the FI relational PostgreSQL runtime boundary")
	generationID := flags.String("generation-id", "", "recorded FI generation ID to ingest")
	sourceID := flags.String("source", "", "authorized FI source ID")
	connectionString := flags.String("postgres", recordingest.DefaultPostgreSQLConnectionString, "FI PostgreSQL connection string")
	custodyRoot := flags.String("generation-custody-root", "/var/lib/fi/custody/generation", "durable FI generation custody root")
	recordedRoot := flags.String("generation-recorded-root", "/var/lib/fi/custody/recorded", "durable FI generation recorder root")
	maxCanonicalBytes := flags.Uint64("generation-max-canonical-bytes", 68719476736, "maximum canonical bytes accepted for ingest")
	maxEncodedBytes := flags.Uint64("generation-max-encoded-bytes", 68719476736, "maximum encoded bytes accepted for ingest")
	maxManifestBytes := flags.Uint64("generation-max-manifest-bytes", 1048576, "maximum collector manifest bytes accepted for ingest")
	_ = flags.Parse(os.Args[1:])

	if flags.NArg() != 0 || (*databaseCheck && (*generationID != "" || *sourceID != "")) || (!*databaseCheck && (*generationID == "" || *sourceID == "")) {
		usage()
	}

	ctx := context.Background()
	connection, state, err := recordingest.OpenPostgreSQL(ctx, *connectionString)
	if err != nil {
		fail(err)
	}
	defer connection.Close(ctx)

	if *databaseCheck {
		fmt.Printf("PostgreSQLUser:       %s\n", state.CurrentUser)
		fmt.Printf("PostgreSQLDatabase:   %s\n", state.CurrentDatabase)
		fmt.Printf("RelationalTables:     %d\n", state.RelationalTables)
		fmt.Printf("SupportedRecordKinds: %d\n", len(recordingest.SupportedRecordKinds()))
		fmt.Printf("IngestVersion:        %s\n", recordingest.IngestVersion)
		fmt.Println("RelationalFoundation: READY")
		fmt.Println("GenerationIngest:     ENABLED")
		return
	}

	attemptID, err := recordingest.NewAttemptID()
	if err != nil {
		fail(err)
	}
	if err := recordingest.WriteAttemptStarted(ctx, connection, attemptID, *sourceID, *generationID); err != nil {
		fail(err)
	}

	generation, err := recordingest.LoadRecordedGeneration(recordingest.GenerationLoadConfig{
		CustodyRoot: *custodyRoot, MaxCanonicalBytes: *maxCanonicalBytes, MaxEncodedBytes: *maxEncodedBytes,
		MaxManifestBytes: *maxManifestBytes, RecordedRoot: *recordedRoot, SourceID: *sourceID,
	}, *generationID)
	if err != nil {
		zero := int64(0)
		journalErr := recordingest.WriteAttemptTerminal(ctx, connection, recordingest.JournalEvent{
			AttemptID: attemptID, SourceID: *sourceID, GenerationID: *generationID, Outcome: "Failed", Stage: "RecorderValidation",
			ReasonCode: "GENERATION_LOAD_FAILED", Detail: err.Error(), RecordsSeen: &zero, RecordsCommitted: &zero,
		})
		fail(errors.Join(err, journalErr))
	}
	defer func() {
		if err := generation.Close(); err != nil {
			fmt.Fprintln(os.Stderr, "WARNING:", err)
		}
	}()

	result, err := recordingest.IngestPreparedGeneration(ctx, connection, attemptID, generation)
	if err != nil {
		fail(err)
	}

	fmt.Printf("AttemptID:            %s\n", result.AttemptID)
	fmt.Printf("Source:               %s\n", result.SourceID)
	fmt.Printf("GenerationID:         %s\n", result.GenerationID)
	fmt.Printf("TransferSHA256:       %s\n", result.TransferSHA256)
	fmt.Printf("ReceiptSHA256:        %s\n", result.ReceiptSHA256)
	fmt.Printf("Batches:              %d\n", result.Batches)
	fmt.Printf("DataBytes:            %d\n", result.DataBytes)
	fmt.Printf("RecordsSeen:          %d\n", result.RecordsSeen)
	fmt.Printf("RecordsCommitted:     %d\n", result.RecordsCommitted)
	fmt.Printf("RecordedGenerationID: %d\n", result.RecordedGenerationID)
	fmt.Printf("Outcome:              %s\n", result.Outcome)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "ERROR:", err)
	os.Exit(1)
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  fi-ingest -database-check [-postgres <connection-string>]")
	fmt.Fprintln(os.Stderr, "  fi-ingest -source <source-id> -generation-id <generation-id> [-postgres <connection-string>]")
	os.Exit(2)
}
