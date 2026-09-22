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
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/recordingest"
	"github.com/jackc/pgx/v5"
)

type workerConfig struct {
	ConnectionString  string
	CustodyRoot       string
	MaxAttempts       uint64
	MaxCanonicalBytes uint64
	MaxEncodedBytes   uint64
	MaxManifestBytes  uint64
	Once              bool
	PollInterval      time.Duration
	RecordedRoot      string
	RetryAfter        time.Duration
	SourceID          string
}

func main() {
	flags := flag.NewFlagSet(
		"fi-ingest-worker",
		flag.ExitOnError,
	)

	sourceID := flags.String(
		"source",
		"",
		"authorized FI source ID",
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
		"maximum canonical bytes accepted for ingest",
	)

	maxEncodedBytes := flags.Uint64(
		"generation-max-encoded-bytes",
		68719476736,
		"maximum encoded bytes accepted for ingest",
	)

	maxManifestBytes := flags.Uint64(
		"generation-max-manifest-bytes",
		1048576,
		"maximum collector manifest bytes accepted for ingest",
	)

	pollInterval := flags.Duration(
		"poll-interval",
		5*time.Second,
		"delay between receipt/database reconcile passes",
	)

	retryAfter := flags.Duration(
		"retry-after",
		15*time.Minute,
		"delay before retrying a source-record rejection",
	)

	once := flags.Bool(
		"once",
		false,
		"perform one reconcile/ingest pass and exit",
	)

	maxAttempts := flags.Uint64(
		"max-attempts",
		0,
		"maximum generation attempts before exit; zero means unlimited",
	)

	_ = flags.Parse(os.Args[1:])

	if flags.NArg() != 0 ||
		strings.TrimSpace(*sourceID) == "" {
		usage()
	}

	if *pollInterval <= 0 {
		fail(
			errors.New(
				"poll-interval must be greater than zero",
			),
		)
	}

	if *retryAfter <= 0 {
		fail(
			errors.New(
				"retry-after must be greater than zero",
			),
		)
	}

	ctx, stop :=
		signal.NotifyContext(
			context.Background(),
			syscall.SIGINT,
			syscall.SIGTERM,
		)
	defer stop()

	config := workerConfig{
		ConnectionString:  *connectionString,
		CustodyRoot:       *custodyRoot,
		MaxAttempts:       *maxAttempts,
		MaxCanonicalBytes: *maxCanonicalBytes,
		MaxEncodedBytes:   *maxEncodedBytes,
		MaxManifestBytes:  *maxManifestBytes,
		Once:              *once,
		PollInterval:      *pollInterval,
		RecordedRoot:      *recordedRoot,
		RetryAfter:        *retryAfter,
		SourceID:          *sourceID,
	}

	if err := runWorker(ctx, config); err != nil &&
		!errors.Is(err, context.Canceled) {
		fail(err)
	}
}

func attemptGeneration(
	ctx context.Context,
	config workerConfig,
	connection postgresConnection,
	item recordingest.ReconcilePlanItem,
) (
	recordingest.IngestResult,
	error,
) {
	candidate := item.Candidate

	attemptID, err :=
		recordingest.NewAttemptID()
	if err != nil {
		return recordingest.IngestResult{}, err
	}

	if err :=
		recordingest.WriteAttemptStarted(
			ctx,
			connection.Connection(),
			attemptID,
			candidate.SourceID,
			candidate.GenerationID,
		); err != nil {
		return recordingest.IngestResult{}, err
	}

	generation, err :=
		recordingest.LoadRecordedGeneration(
			recordingest.GenerationLoadConfig{
				CustodyRoot: config.CustodyRoot,

				MaxCanonicalBytes: config.MaxCanonicalBytes,
				MaxEncodedBytes:   config.MaxEncodedBytes,
				MaxManifestBytes:  config.MaxManifestBytes,

				RecordedRoot: config.RecordedRoot,
				SourceID:     candidate.SourceID,
			},
			candidate.GenerationID,
		)

	if err != nil {
		zero := int64(0)

		journalErr :=
			recordingest.WriteAttemptTerminal(
				ctx,
				connection.Connection(),
				recordingest.JournalEvent{
					AttemptID:        attemptID,
					SourceID:         candidate.SourceID,
					GenerationID:     candidate.GenerationID,
					Outcome:          "Failed",
					Stage:            "RecorderValidation",
					ReasonCode:       "GENERATION_LOAD_FAILED",
					Detail:           err.Error(),
					RecordsSeen:      &zero,
					RecordsCommitted: &zero,
				},
			)

		return recordingest.IngestResult{},
			errors.Join(
				fmt.Errorf(
					"load recorded generation %q: %w",
					candidate.GenerationID,
					err,
				),
				journalErr,
			)
	}

	result, ingestErr :=
		recordingest.IngestPreparedGeneration(
			ctx,
			connection.Connection(),
			attemptID,
			generation,
		)

	closeErr := generation.Close()
	if closeErr != nil {
		fmt.Fprintf(
			os.Stderr,
			"WARNING: close staged generation %s: %v\n",
			candidate.GenerationID,
			closeErr,
		)
	}

	return result, ingestErr
}

type postgresConnection struct {
	connection *pgx.Conn
}

func (value postgresConnection) Connection() *pgx.Conn {
	return value.connection
}

func runWorker(
	ctx context.Context,
	config workerConfig,
) error {
	connection, state, err :=
		recordingest.OpenPostgreSQL(
			ctx,
			config.ConnectionString,
		)
	if err != nil {
		return err
	}
	defer connection.Close(context.Background())

	db := postgresConnection{
		connection: connection,
	}

	fmt.Println("===== FI RELATIONAL INGEST WORKER =====")
	fmt.Printf("Source:               %s\n", config.SourceID)
	fmt.Printf("PostgreSQLUser:       %s\n", state.CurrentUser)
	fmt.Printf("PostgreSQLDatabase:   %s\n", state.CurrentDatabase)
	fmt.Printf("RelationalTables:     %d\n", state.RelationalTables)
	fmt.Printf("PollInterval:         %s\n", config.PollInterval)
	fmt.Printf("RetryAfter:           %s\n", config.RetryAfter)
	fmt.Printf("RetryState:           durable ingest journal\n")
	fmt.Printf("Started:              %s\n", time.Now().Format(time.RFC3339))
	fmt.Println()

	startupPlan, err :=
		recordingest.PlanRecordedGenerations(
			ctx,
			connection,
			config.RecordedRoot,
			config.SourceID,
		)
	if err != nil {
		return err
	}

	fmt.Printf(
		"STARTUP RECONCILE discovered=%d accepted=%d pending=%d conflict=%d\n",
		startupPlan.Discovered,
		startupPlan.Accepted,
		startupPlan.Pending,
		startupPlan.Conflict,
	)

	if err := reconcileConflictError(startupPlan); err != nil {
		return err
	}

	fmt.Println()

	var totalAttempts uint64

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		plan, err :=
			recordingest.PlanRecordedGenerationsForIngest(
				ctx,
				connection,
				config.RecordedRoot,
				config.SourceID,
			)
		if err != nil {
			return err
		}

		fmt.Printf(
			"PLAN time=%s discovered=%d accepted=%d pending=%d conflict=%d\n",
			time.Now().Format(time.RFC3339),
			plan.Discovered,
			plan.Accepted,
			plan.Pending,
			plan.Conflict,
		)

		if err := reconcileConflictError(plan); err != nil {
			return err
		}

		rejectionTimes, err :=
			recordingest.LoadSourceRecordRejectionTimes(
				ctx,
				connection,
				config.SourceID,
				pendingGenerationIDs(plan),
			)
		if err != nil {
			return err
		}

		pending, deferredCount, err :=
			selectPending(
				plan,
				time.Now(),
				rejectionTimes,
				config.RetryAfter,
			)
		if err != nil {
			return err
		}

		if deferredCount != 0 {
			fmt.Printf(
				"DEFERRED count=%d source=journal retry_after=%s\n",
				deferredCount,
				config.RetryAfter,
			)
		}

		for _, item := range pending {
			if config.MaxAttempts != 0 &&
				totalAttempts >= config.MaxAttempts {
				fmt.Printf(
					"MaxAttempts reached: %d\n",
					totalAttempts,
				)
				return nil
			}

			candidate := item.Candidate

			fmt.Printf(
				"INGEST START source=%s generation=%s records=%d bytes=%d time=%s\n",
				candidate.SourceID,
				candidate.GenerationID,
				candidate.RecordCount,
				candidate.DataBytes,
				time.Now().Format(time.RFC3339),
			)

			start := time.Now()

			result, attemptErr :=
				attemptGeneration(
					ctx,
					config,
					db,
					item,
				)

			totalAttempts++

			if attemptErr != nil {
				if errors.Is(
					attemptErr,
					recordingest.ErrSourceRecordRejected,
				) {
					fmt.Fprintf(
						os.Stderr,
						"INGEST REJECTED generation=%s elapsed=%s retry_after=%s retry_state=journal error=%v\n",
						candidate.GenerationID,
						time.Since(start).Round(time.Millisecond),
						config.RetryAfter,
						attemptErr,
					)

					continue
				}

				return fmt.Errorf(
					"generation %q ingest failed: %w",
					candidate.GenerationID,
					attemptErr,
				)
			}

			fmt.Printf(
				"INGEST FINISH generation=%s outcome=%s records_seen=%d records_committed=%d elapsed=%s\n",
				result.GenerationID,
				result.Outcome,
				result.RecordsSeen,
				result.RecordsCommitted,
				time.Since(start).Round(time.Millisecond),
			)
		}

		if config.Once {
			return nil
		}

		timer :=
			time.NewTimer(
				config.PollInterval,
			)

		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()

		case <-timer.C:
		}
	}
}

func pendingGenerationIDs(
	plan recordingest.ReconcilePlan,
) []string {
	generationIDs :=
		make(
			[]string,
			0,
			plan.Pending,
		)

	for _, item := range plan.Items {
		if item.State !=
			recordingest.ReconcileStatePending {
			continue
		}

		generationIDs =
			append(
				generationIDs,
				item.Candidate.GenerationID,
			)
	}

	return generationIDs
}

func reconcileConflictError(
	plan recordingest.ReconcilePlan,
) error {
	for _, item := range plan.Items {
		if item.State ==
			recordingest.ReconcileStateConflict {
			return fmt.Errorf(
				"FI relational reconcile conflict for source=%q generation=%q: %s",
				item.Candidate.SourceID,
				item.Candidate.GenerationID,
				item.Detail,
			)
		}
	}

	return nil
}

func selectPending(
	plan recordingest.ReconcilePlan,
	now time.Time,
	rejectionTimes map[string]time.Time,
	retryAfter time.Duration,
) (
	[]recordingest.ReconcilePlanItem,
	int,
	error,
) {
	if err := reconcileConflictError(plan); err != nil {
		return nil, 0, err
	}

	pending :=
		make(
			[]recordingest.ReconcilePlanItem,
			0,
			plan.Pending,
		)

	deferredCount := 0

	for _, item := range plan.Items {
		if item.State !=
			recordingest.ReconcileStatePending {
			continue
		}

		rejectedAt, found :=
			rejectionTimes[item.Candidate.GenerationID]

		if found &&
			now.Before(
				rejectedAt.Add(
					retryAfter,
				),
			) {
			deferredCount++
			continue
		}

		pending =
			append(
				pending,
				item,
			)
	}

	return pending, deferredCount, nil
}

func fail(err error) {
	fmt.Fprintln(
		os.Stderr,
		"ERROR:",
		err,
	)

	os.Exit(1)
}

func usage() {
	fmt.Fprintln(
		os.Stderr,
		"usage:",
	)

	fmt.Fprintln(
		os.Stderr,
		"  fi-ingest-worker -source <source-id> [options]",
	)

	os.Exit(2)
}
