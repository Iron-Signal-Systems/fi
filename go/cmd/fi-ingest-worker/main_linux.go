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
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/generationready"
	"github.com/Iron-Signal-Systems/fi/go/internal/generationrecorder"
	"github.com/Iron-Signal-Systems/fi/go/internal/recordingest"
	"github.com/Iron-Signal-Systems/fi/go/internal/workerlock"
	"github.com/jackc/pgx/v5"
)

type workerConfig struct {
	ConnectionString  string
	CustodyRoot       string
	LockFile          string
	MaxAttempts       uint64
	MaxCanonicalBytes uint64
	MaxEncodedBytes   uint64
	MaxManifestBytes  uint64
	Once              bool
	PollInterval      time.Duration
	ReadyBatchSize    uint64
	ReadyRoot         string
	RecordedRoot      string
	RepairInterval    time.Duration
	RetryAfter        time.Duration
	RetryBatchSize    uint64
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

	lockFile := flags.String(
		"lock-file",
		"/run/fi/fi-ingest-worker.lock",
		"exclusive FI relational ingest worker lock file",
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

	readyRoot := flags.String(
		"generation-ready-root",
		"/var/lib/fi/custody/ready",
		"non-authoritative FI generation ingest-ready root",
	)

	readyBatchSize := flags.Uint64(
		"ready-batch-size",
		64,
		"maximum ingest-ready markers inspected per polling pass",
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

	retryBatchSize := flags.Uint64(
		"retry-batch-size",
		64,
		"maximum due source-record retries inspected per polling pass",
	)

	repairInterval := flags.Duration(
		"repair-interval",
		time.Hour,
		"validation interval for adaptive full authoritative receipt repair sweeps",
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

	if *retryBatchSize == 0 {
		fail(
			errors.New(
				"retry-batch-size must be greater than zero",
			),
		)
	}

	if *readyBatchSize == 0 {
		fail(
			errors.New(
				"ready-batch-size must be greater than zero",
			),
		)
	}

	if *repairInterval <= 0 {
		fail(
			errors.New(
				"repair-interval must be greater than zero",
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
		LockFile:          *lockFile,
		MaxAttempts:       *maxAttempts,
		MaxCanonicalBytes: *maxCanonicalBytes,
		MaxEncodedBytes:   *maxEncodedBytes,
		MaxManifestBytes:  *maxManifestBytes,
		Once:              *once,
		PollInterval:      *pollInterval,
		ReadyBatchSize:    *readyBatchSize,
		ReadyRoot:         *readyRoot,
		RecordedRoot:      *recordedRoot,
		RepairInterval:    *repairInterval,
		RetryAfter:        *retryAfter,
		RetryBatchSize:    *retryBatchSize,
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
) (runErr error) {
	singleton, err := workerlock.Acquire(config.LockFile)
	if err != nil {
		return err
	}
	defer func() {
		runErr = errors.Join(runErr, singleton.Close())
	}()

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

	repair := newRepairCadence(config.RepairInterval)

	fmt.Println("===== FI RELATIONAL INGEST WORKER =====")
	fmt.Printf("Source:               %s\n", config.SourceID)
	fmt.Printf("PostgreSQLUser:       %s\n", state.CurrentUser)
	fmt.Printf("PostgreSQLDatabase:   %s\n", state.CurrentDatabase)
	fmt.Printf("RelationalTables:     %d\n", state.RelationalTables)
	fmt.Printf("SingletonLock:        %s\n", singleton.Path())
	fmt.Printf("PollInterval:         %s\n", config.PollInterval)
	fmt.Printf("ReadyRoot:            %s\n", config.ReadyRoot)
	fmt.Printf("ReadyBatchSize:       %d\n", config.ReadyBatchSize)
	fmt.Printf("RepairMode:           %s\n", repair.Mode())
	fmt.Printf("RepairValidation:     %s\n", repair.Interval())
	fmt.Printf("RepairCleanTarget:    %d\n", repairValidationCleanTarget)
	fmt.Printf("RepairIntermediate:   %s\n", repairIntermediateInterval)
	fmt.Printf("RepairSteady:         %s\n", repairSteadyInterval)
	fmt.Printf("RetryAfter:           %s\n", config.RetryAfter)
	fmt.Printf("RetryBatchSize:       %d\n", config.RetryBatchSize)
	fmt.Printf("RetryState:           durable ingest journal\n")
	fmt.Printf("Started:              %s\n", time.Now().Format(time.RFC3339))
	fmt.Println()

	startupPlan, err :=
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
		"STARTUP RECONCILE discovered=%d accepted=%d pending=%d conflict=%d\n",
		startupPlan.Discovered,
		startupPlan.Accepted,
		startupPlan.Pending,
		startupPlan.Conflict,
	)

	if err := reconcileConflictError(startupPlan); err != nil {
		return err
	}

	var totalAttempts uint64
	if err := processPlan(
		ctx,
		config,
		db,
		startupPlan,
		false,
		&totalAttempts,
	); err != nil {
		return err
	}
	if config.MaxAttempts != 0 && totalAttempts >= config.MaxAttempts {
		return nil
	}

	fmt.Println()

	nextRepair := time.Now().Add(repair.Interval())

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		now := time.Now()
		if !now.Before(nextRepair) {
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

			assessment, err :=
				assessRepairPlan(
					ctx,
					config,
					connection,
					plan,
				)
			if err != nil {
				return err
			}

			fmt.Printf(
				"REPAIR PLAN time=%s mode=%s interval=%s discovered=%d accepted=%d pending=%d conflict=%d ready_notified=%d known_rejected=%d unexpected_pending=%d\n",
				now.Format(time.RFC3339),
				repair.Mode(),
				repair.Interval(),
				plan.Discovered,
				plan.Accepted,
				plan.Pending,
				plan.Conflict,
				assessment.ReadyNotified,
				assessment.KnownRejected,
				assessment.UnexpectedPending,
			)

			if err := processPlan(
				ctx,
				config,
				db,
				plan,
				false,
				&totalAttempts,
			); err != nil {
				return err
			}

			result := "Clean"
			if !assessment.Clean() {
				result = "Anomaly"
			}

			repair.Observe(assessment.Clean())

			fmt.Printf(
				"REPAIR CADENCE result=%s mode=%s interval=%s clean_count=%d\n",
				result,
				repair.Mode(),
				repair.Interval(),
				repair.CleanCount(),
			)

			nextRepair = time.Now().Add(repair.Interval())
		} else {
			plan, markerCount, err := readyPlan(
				ctx,
				config,
				connection,
			)
			if err != nil {
				return err
			}

			fmt.Printf(
				"READY PLAN time=%s markers=%d accepted=%d pending=%d conflict=%d\n",
				now.Format(time.RFC3339),
				markerCount,
				plan.Accepted,
				plan.Pending,
				plan.Conflict,
			)

			if err := processPlan(
				ctx,
				config,
				db,
				plan,
				true,
				&totalAttempts,
			); err != nil {
				return err
			}
		}

		retryPlan, dueCount, err := dueRetryPlan(
			ctx,
			config,
			connection,
			now,
		)
		if err != nil {
			return err
		}

		if dueCount != 0 {
			fmt.Printf(
				"RETRY PLAN time=%s due=%d accepted=%d pending=%d conflict=%d\n",
				now.Format(time.RFC3339),
				dueCount,
				retryPlan.Accepted,
				retryPlan.Pending,
				retryPlan.Conflict,
			)

			if err := processPlan(
				ctx,
				config,
				db,
				retryPlan,
				false,
				&totalAttempts,
			); err != nil {
				return err
			}
		}

		if config.MaxAttempts != 0 &&
			totalAttempts >= config.MaxAttempts {
			return nil
		}

		if config.Once {
			return nil
		}

		timer := time.NewTimer(config.PollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func processPlan(
	ctx context.Context,
	config workerConfig,
	connection postgresConnection,
	plan recordingest.ReconcilePlan,
	retireReady bool,
	totalAttempts *uint64,
) error {
	if totalAttempts == nil {
		return errors.New("FI ingest worker total-attempt counter is required")
	}

	if err := reconcileConflictError(plan); err != nil {
		return err
	}

	retireNames := make([]string, 0, plan.Accepted+plan.Pending)
	if retireReady {
		for _, item := range plan.Items {
			if item.State == recordingest.ReconcileStateAccepted {
				retireNames = append(
					retireNames,
					filepath.Base(item.Candidate.Path),
				)
			}
		}
	}

	flushReady := func() error {
		if !retireReady || len(retireNames) == 0 {
			return nil
		}

		if err := generationready.RemoveReceiptNames(
			config.ReadyRoot,
			retireNames,
		); err != nil {
			return err
		}
		retireNames = retireNames[:0]
		return nil
	}

	if plan.Pending == 0 {
		return flushReady()
	}

	rejectionTimes, err :=
		recordingest.LoadSourceRecordRejectionTimes(
			ctx,
			connection.Connection(),
			config.SourceID,
			pendingGenerationIDs(plan),
		)
	if err != nil {
		return err
	}

	pending, deferred, err :=
		selectPending(
			plan,
			time.Now(),
			rejectionTimes,
			config.RetryAfter,
		)
	if err != nil {
		return err
	}

	if len(deferred) != 0 {
		fmt.Printf(
			"DEFERRED count=%d source=journal retry_after=%s\n",
			len(deferred),
			config.RetryAfter,
		)

		if retireReady {
			for _, item := range deferred {
				retireNames = append(
					retireNames,
					filepath.Base(item.Candidate.Path),
				)
			}
		}
	}

	for _, item := range pending {
		if config.MaxAttempts != 0 &&
			*totalAttempts >= config.MaxAttempts {
			if err := flushReady(); err != nil {
				return err
			}
			fmt.Printf(
				"MaxAttempts reached: %d\n",
				*totalAttempts,
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
				connection,
				item,
			)

		(*totalAttempts)++

		if attemptErr != nil {
			if errors.Is(
				attemptErr,
				recordingest.ErrSourceRecordRejected,
			) {
				recorded, verifyErr :=
					recordingest.SourceRecordRejectionRecorded(
						ctx,
						connection.Connection(),
						result.AttemptID,
						candidate.SourceID,
						candidate.GenerationID,
					)
				if verifyErr != nil || !recorded {
					flushErr := flushReady()
					retryStateErr := verifyErr
					if retryStateErr == nil {
						retryStateErr = errors.New(
							"durable SOURCE_RECORD_REJECTED journal event was not found",
						)
					}

					return errors.Join(
						fmt.Errorf(
							"generation %q source-record rejection retry state is not durable: %w",
							candidate.GenerationID,
							retryStateErr,
						),
						flushErr,
					)
				}

				if retireReady {
					retireNames = append(
						retireNames,
						filepath.Base(candidate.Path),
					)
				}

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

			if err := flushReady(); err != nil {
				return errors.Join(
					fmt.Errorf(
						"generation %q ingest failed: %w",
						candidate.GenerationID,
						attemptErr,
					),
					err,
				)
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

		if retireReady {
			retireNames = append(
				retireNames,
				filepath.Base(candidate.Path),
			)
		}
	}

	return flushReady()
}

func dueRetryPlan(
	ctx context.Context,
	config workerConfig,
	connection *pgx.Conn,
	now time.Time,
) (
	recordingest.ReconcilePlan,
	uint64,
	error,
) {
	generationIDs, err :=
		recordingest.LoadDueSourceRecordRetryGenerationIDs(
			ctx,
			connection,
			config.SourceID,
			now.Add(-config.RetryAfter),
			config.RetryBatchSize,
		)
	if err != nil {
		return recordingest.ReconcilePlan{}, 0, err
	}
	if len(generationIDs) == 0 {
		return recordingest.ReconcilePlan{}, 0, nil
	}

	names := make([]string, len(generationIDs))
	for index, generationID := range generationIDs {
		names[index] =
			generationrecorder.RecordedReceiptObjectName(
				config.SourceID,
				generationID,
			)
	}

	candidates, err := recordingest.DiscoverRecordedReceiptsByName(
		config.RecordedRoot,
		names,
		config.SourceID,
	)
	if err != nil {
		return recordingest.ReconcilePlan{}, uint64(len(generationIDs)), err
	}

	ordered, err := orderRetryCandidates(
		generationIDs,
		candidates,
	)
	if err != nil {
		return recordingest.ReconcilePlan{}, uint64(len(generationIDs)), err
	}

	plan, err := recordingest.PlanRecordedReceiptCandidatesForIngest(
		ctx,
		connection,
		config.SourceID,
		ordered,
	)
	if err != nil {
		return recordingest.ReconcilePlan{}, uint64(len(generationIDs)), err
	}

	return plan, uint64(len(generationIDs)), nil
}

func orderRetryCandidates(
	generationIDs []string,
	candidates []recordingest.RecordedReceiptCandidate,
) ([]recordingest.RecordedReceiptCandidate, error) {
	if len(generationIDs) != len(candidates) {
		return nil, fmt.Errorf(
			"FI retry plan selected %d generations but %d authoritative receipts were discovered",
			len(generationIDs),
			len(candidates),
		)
	}

	byGeneration := make(
		map[string]recordingest.RecordedReceiptCandidate,
		len(candidates),
	)
	for _, candidate := range candidates {
		if _, found := byGeneration[candidate.GenerationID]; found {
			return nil, fmt.Errorf(
				"FI retry plan discovered generation %q more than once",
				candidate.GenerationID,
			)
		}
		byGeneration[candidate.GenerationID] = candidate
	}

	ordered := make(
		[]recordingest.RecordedReceiptCandidate,
		0,
		len(generationIDs),
	)
	for _, generationID := range generationIDs {
		candidate, found := byGeneration[generationID]
		if !found {
			return nil, fmt.Errorf(
				"FI retry plan authoritative receipt for generation %q was not discovered",
				generationID,
			)
		}
		ordered = append(ordered, candidate)
	}

	return ordered, nil
}

func readyPlan(
	ctx context.Context,
	config workerConfig,
	connection *pgx.Conn,
) (
	recordingest.ReconcilePlan,
	uint64,
	error,
) {
	names, err := generationready.ReadReceiptNames(
		config.ReadyRoot,
		config.ReadyBatchSize,
	)
	if err != nil {
		return recordingest.ReconcilePlan{}, 0, err
	}
	if len(names) == 0 {
		return recordingest.ReconcilePlan{}, 0, nil
	}

	candidates, err := recordingest.DiscoverRecordedReceiptsByName(
		config.RecordedRoot,
		names,
		config.SourceID,
	)
	if err != nil {
		return recordingest.ReconcilePlan{}, 0, err
	}
	if len(candidates) != len(names) {
		return recordingest.ReconcilePlan{},
			uint64(len(names)),
			fmt.Errorf(
				"FI ingest-ready batch selected %d markers but %d authoritative receipts matched source %q",
				len(names),
				len(candidates),
				config.SourceID,
			)
	}

	plan, err := recordingest.PlanRecordedReceiptCandidatesForIngest(
		ctx,
		connection,
		config.SourceID,
		candidates,
	)
	if err != nil {
		return recordingest.ReconcilePlan{}, uint64(len(names)), err
	}

	return plan, uint64(len(names)), nil
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
	[]recordingest.ReconcilePlanItem,
	error,
) {
	if err := reconcileConflictError(plan); err != nil {
		return nil, nil, err
	}

	pending :=
		make(
			[]recordingest.ReconcilePlanItem,
			0,
			plan.Pending,
		)

	deferred :=
		make(
			[]recordingest.ReconcilePlanItem,
			0,
			plan.Pending,
		)

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
			deferred = append(
				deferred,
				item,
			)
			continue
		}

		pending =
			append(
				pending,
				item,
			)
	}

	return pending, deferred, nil
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
