// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

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
	"github.com/Iron-Signal-Systems/fi/go/internal/receivertrust"
	"github.com/Iron-Signal-Systems/fi/go/internal/recordingest"
	"github.com/jackc/pgx/v5"
)

type workerConfig struct {
	ConnectionString       string
	CustodyRoot            string
	LockFile               string
	DualLockTransition     bool
	MaxAttempts            uint64
	MaxCanonicalBytes      uint64
	MaxEncodedBytes        uint64
	MaxManifestBytes       uint64
	Once                   bool
	PollInterval           time.Duration
	PostgreSQLRetryInitial time.Duration
	PostgreSQLRetryMax     time.Duration
	QuarantineRoot         string
	ReadyBatchSize         uint64
	ReadyRoot              string
	RecordedRoot           string
	SourceNamespaces       bool
	RepairInterval         time.Duration
	RetryAfter             time.Duration
	RetryBatchSize         uint64
	SourceID               string
	SourceIDs              []string
}

func main() {
	if len(os.Args) > 1 &&
		os.Args[1] == "quarantine-release" {
		if err := m1RunQuarantineReleaseCommand(
			os.Args[2:],
			os.Stdout,
		); err != nil {
			fail(err)
		}
		return
	}

	flags := flag.NewFlagSet(
		"fi-ingest-worker",
		flag.ExitOnError,
	)

	connectionString := flags.String(
		"postgres",
		recordingest.DefaultPostgreSQLConnectionString,
		"FI PostgreSQL connection string",
	)

	postgreSQLRetryInitial := flags.Duration(
		"postgres-retry-initial",
		time.Second,
		"initial delay before retrying PostgreSQL availability failures",
	)

	postgreSQLRetryMax := flags.Duration(
		"postgres-retry-max",
		30*time.Second,
		"maximum delay between PostgreSQL availability retries",
	)

	lockFile := flags.String(
		"lock-file",
		"/var/run/fi/fi-ingest-worker.lock",
		"exclusive FI relational ingest worker lock file",
	)

	dualLockTransition := flags.Bool(
		"lock-migration-dual",
		false,
		"transition only: hold legacy and keeper-owned singleton locks; fails closed if either is unavailable",
	)

	custodyRoot := flags.String(
		"generation-custody-root",
		"/var/db/fi/custody/generation",
		"durable FI generation custody root",
	)

	recordedRoot := flags.String(
		"generation-recorded-root",
		"/var/db/fi/custody/recorded",
		"durable FI generation recorder root",
	)

	readyRoot := flags.String(
		"generation-ready-root",
		"/var/db/fi/custody/ready",
		"non-authoritative FI generation ingest-ready root",
	)

	sourceNamespaces := flags.Bool(
		"generation-source-namespaces",
		false,
		"enable authoritative per-source recorder namespaces; requires completed migration",
	)

	quarantineRoot := flags.String(
		"quarantine-state-root",
		"",
		"pre-provisioned persistent worker-owned quarantine directory; required for namespaces",
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

	if flags.NArg() != 0 {
		usage()
	}

	if *pollInterval <= 0 {
		fail(
			errors.New(
				"poll-interval must be greater than zero",
			),
		)
	}

	if *postgreSQLRetryInitial <= 0 {
		fail(
			errors.New(
				"postgres-retry-initial must be greater than zero",
			),
		)
	}

	if *postgreSQLRetryMax < *postgreSQLRetryInitial {
		fail(
			errors.New(
				"postgres-retry-max must be greater than or equal to postgres-retry-initial",
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

	// Reject incomplete namespace activation before reading
	// the installed trust registry or opening PostgreSQL.
	if *sourceNamespaces && *quarantineRoot == "" {
		fail(errors.New(
			"generation-source-namespaces requires quarantine-state-root",
		))
	}
	if !*sourceNamespaces && *quarantineRoot != "" {
		fail(errors.New(
			"quarantine-state-root requires generation-source-namespaces",
		))
	}
	if *dualLockTransition && *sourceNamespaces {
		fail(errors.New("lock-migration-dual cannot be combined with namespaced ingest"))
	}
	if *dualLockTransition && *lockFile != m8LegacyLockPath {
		fail(fmt.Errorf("lock-migration-dual requires legacy lock %q", m8LegacyLockPath))
	}

	batchIssuer, err := receivertrust.LoadCertificate(
		receivertrust.BatchIssuerPath,
	)
	if err != nil {
		fail(err)
	}

	sourceRegistry, err := receivertrust.LoadBatchSourceRegistry(
		receivertrust.SourceRegistryPath,
		batchIssuer,
	)
	if err != nil {
		fail(err)
	}

	sourceIDs := sourceRegistry.EnabledSourceIDs()

	if len(sourceIDs) == 0 {
		fail(
			errors.New(
				"FI ingest source registry contains no enabled sources",
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
		ConnectionString:       *connectionString,
		CustodyRoot:            *custodyRoot,
		LockFile:               *lockFile,
		DualLockTransition:     *dualLockTransition,
		MaxAttempts:            *maxAttempts,
		MaxCanonicalBytes:      *maxCanonicalBytes,
		MaxEncodedBytes:        *maxEncodedBytes,
		MaxManifestBytes:       *maxManifestBytes,
		Once:                   *once,
		PollInterval:           *pollInterval,
		PostgreSQLRetryInitial: *postgreSQLRetryInitial,
		PostgreSQLRetryMax:     *postgreSQLRetryMax,
		ReadyBatchSize:         *readyBatchSize,
		ReadyRoot:              *readyRoot,
		RecordedRoot:           *recordedRoot,
		SourceNamespaces:       *sourceNamespaces,
		QuarantineRoot:         *quarantineRoot,
		RepairInterval:         *repairInterval,
		RetryAfter:             *retryAfter,
		RetryBatchSize:         *retryBatchSize,
		SourceIDs:              sourceIDs,
	}

	if err := m1ValidateMaintenancePathAgreement(config); err != nil {
		fail(err)
	}

	// M1 namespaced activation is blocked until independent
	// quarantine publication and release authority is installed.
	if err := m1ValidateQuarantineAuthorityReady(config); err != nil {
		fail(err)
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

				RecordedRoot:     config.RecordedRoot,
				SourceNamespaces: config.SourceNamespaces,
				SourceID:         candidate.SourceID,
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
	if config.SourceNamespaces {
		if err := validateWorkerSourceNamespaces(config); err != nil {
			return err
		}
	}

	if err := m1ValidateQuarantineConfiguration(config); err != nil {
		return err
	}

	singleton, err := m1AcquireWorkerSingleton(config)
	if err != nil {
		return err
	}
	defer func() {
		runErr = errors.Join(runErr, singleton.Close())
	}()

	backoff, err := newPostgreSQLBackoff(
		config.PostgreSQLRetryInitial,
		config.PostgreSQLRetryMax,
	)
	if err != nil {
		return err
	}

	states, err := newSourceSessionStates(config)
	if err != nil {
		return err
	}

	if config.SourceNamespaces {
		keeperClient, err := m1NewWorkerKeeperClient()
		if err != nil {
			return fmt.Errorf("resolve independent keeper authority: %w", err)
		}
		if err := m1RestoreSourceKeeperStates(ctx, states, keeperClient); err != nil {
			return fmt.Errorf("restore keeper-owned source quarantine: %w", err)
		}
	}

	fmt.Println("===== FI RELATIONAL INGEST WORKER =====")
	fmt.Printf("Sources:                %d\n", len(config.SourceIDs))
	for index, sourceID := range config.SourceIDs {
		fmt.Printf(
			"Source[%d]:              %s\n",
			index,
			sourceID,
		)
	}
	fmt.Printf("SingletonLock:          %s\n", singleton.Path())
	fmt.Printf("PostgreSQLRetryInitial: %s\n", config.PostgreSQLRetryInitial)
	fmt.Printf("PostgreSQLRetryMax:     %s\n", config.PostgreSQLRetryMax)
	fmt.Printf("PollInterval:           %s\n", config.PollInterval)
	fmt.Printf("ReadyRoot:              %s\n", config.ReadyRoot)
	fmt.Printf("ReadyBatchSize:         %d\n", config.ReadyBatchSize)
	fmt.Printf("RepairValidation:       %s\n", config.RepairInterval)
	fmt.Printf("RepairCleanTarget:      %d\n", repairValidationCleanTarget)
	fmt.Printf("RepairIntermediate:     %s\n", repairIntermediateInterval)
	fmt.Printf("RepairSteady:           %s\n", repairSteadyInterval)
	fmt.Printf("RetryAfter:             %s\n", config.RetryAfter)
	fmt.Printf("RetryBatchSize:         %d\n", config.RetryBatchSize)
	fmt.Printf("RetryState:             durable ingest journal\n")
	fmt.Printf("Started:                %s\n", time.Now().Format(time.RFC3339))
	fmt.Println()

	var (
		connectedOnce bool
		totalAttempts uint64
	)

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		connection, state, err :=
			recordingest.OpenPostgreSQL(
				ctx,
				config.ConnectionString,
			)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			if !recordingest.IsPostgreSQLUnavailable(err) {
				return err
			}

			delay := backoff.Next()
			fmt.Fprintf(
				os.Stderr,
				"POSTGRES UNAVAILABLE phase=connect retry_in=%s error=%v\n",
				delay,
				err,
			)

			if err := waitPostgreSQLRetry(ctx, delay); err != nil {
				return err
			}
			continue
		}

		status := "CONNECTED"
		if connectedOnce {
			status = "RECONNECTED"
		}
		connectedOnce = true
		backoff.Reset()

		fmt.Printf(
			"POSTGRES %s user=%s database=%s tables=%d time=%s\n",
			status,
			state.CurrentUser,
			state.CurrentDatabase,
			state.RelationalTables,
			time.Now().Format(time.RFC3339),
		)

		sessionErr :=
			runPostgreSQLSession(
				ctx,
				config,
				connection,
				states,
				&totalAttempts,
			)

		closeErr := connection.Close(context.Background())
		if sessionErr == nil {
			if closeErr != nil {
				fmt.Fprintf(
					os.Stderr,
					"WARNING: close FI PostgreSQL session: %v\n",
					closeErr,
				)
			}
			return nil
		}

		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}

		if !recordingest.IsPostgreSQLUnavailable(sessionErr) {
			return sessionErr
		}

		delay := backoff.Next()

		fmt.Fprintf(
			os.Stderr,
			"POSTGRES CONNECTION LOST retry_in=%s error=%v\n",
			delay,
			sessionErr,
		)
		if closeErr != nil {
			fmt.Fprintf(
				os.Stderr,
				"WARNING: close failed PostgreSQL session: %v\n",
				closeErr,
			)
		}

		if err := waitPostgreSQLRetry(ctx, delay); err != nil {
			return err
		}
	}
}

type sourceSessionState struct {
	Config          workerConfig
	NextRepair      time.Time
	Quarantined     bool
	QuarantineStore *m1QuarantineStore // Isolated pre-keeper test fixture only.
	KeeperClient    m1WorkerKeeperClient
	Repair          repairCadence
}

func newSourceSessionStates(
	config workerConfig,
) (
	[]sourceSessionState,
	error,
) {
	if len(config.SourceIDs) == 0 {
		return nil,
			errors.New(
				"FI ingest worker requires at least one enabled source",
			)
	}

	states := make(
		[]sourceSessionState,
		0,
		len(config.SourceIDs),
	)

	for _, sourceID := range config.SourceIDs {
		if strings.TrimSpace(sourceID) == "" {
			return nil,
				errors.New(
					"FI ingest worker source registry contains an empty source ID",
				)
		}

		sourceConfig := config
		sourceConfig.SourceID = sourceID
		sourceConfig.SourceIDs = nil

		states = append(
			states,
			sourceSessionState{
				Config: sourceConfig,
				Repair: newRepairCadence(
					config.RepairInterval,
				),
			},
		)
	}

	return states, nil
}

func runPostgreSQLSession(
	ctx context.Context,
	config workerConfig,
	connection *pgx.Conn,
	states []sourceSessionState,
	totalAttempts *uint64,
) error {
	if connection == nil {
		return errors.New(
			"FI ingest worker PostgreSQL session connection is required",
		)
	}

	if totalAttempts == nil {
		return errors.New(
			"FI ingest worker total-attempt counter is required",
		)
	}

	if len(states) != len(config.SourceIDs) ||
		len(states) == 0 {
		return errors.New(
			"FI ingest session source state count mismatch",
		)
	}

	for index, sourceID := range config.SourceIDs {
		if states[index].Config.SourceID != sourceID {
			return errors.New(
				"FI ingest session source state identity mismatch",
			)
		}
	}

	db := postgresConnection{
		connection: connection,
	}

	for index := range states {
		state := &states[index]

		if err := m1CheckKeeperState(ctx, state); err != nil {
			return err
		}
		if state.Quarantined {
			fmt.Printf(
				"POSTGRES SOURCE QUARANTINED source=%s action=operator_review_required\n",
				state.Config.SourceID,
			)
			continue
		}

		fmt.Printf(
			"POSTGRES SOURCE STARTUP source=%s repair_mode=%s repair_interval=%s clean_count=%d\n",
			state.Config.SourceID,
			state.Repair.Mode(),
			state.Repair.Interval(),
			state.Repair.CleanCount(),
		)

		startupPlan, err := workerRecordedSourcePlan(
			ctx,
			connection,
			state.Config,
		)
		if err != nil {
			if err := quarantineSourceConflict(state, err); err != nil {
				return err
			}
			continue
		}

		fmt.Printf(
			"STARTUP RECONCILE source=%s discovered=%d accepted=%d pending=%d conflict=%d\n",
			state.Config.SourceID,
			startupPlan.Discovered,
			startupPlan.Accepted,
			startupPlan.Pending,
			startupPlan.Conflict,
		)

		if err := runStartupSourcePlan(
			state,
			startupPlan,
			func() error {
				return processPlan(
					ctx,
					state.Config,
					db,
					startupPlan,
					false,
					totalAttempts,
				)
			},
		); err != nil {
			return err
		}
		if state.Quarantined {
			continue
		}

		state.NextRepair =
			time.Now().Add(
				state.Repair.Interval(),
			)

		if config.MaxAttempts != 0 &&
			*totalAttempts >= config.MaxAttempts {
			return nil
		}
	}

	fmt.Println()

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		for index := range states {
			if err := m1CheckKeeperState(ctx, &states[index]); err != nil {
				return err
			}
			if err := runScheduledSourcePass(
				&states[index],
				func(state *sourceSessionState) error {
					return runSourcePass(
						ctx,
						state,
						connection,
						db,
						totalAttempts,
					)
				},
			); err != nil {
				return err
			}

			if config.MaxAttempts != 0 &&
				*totalAttempts >= config.MaxAttempts {
				return nil
			}
		}

		if config.Once {
			return nil
		}

		timer := time.NewTimer(
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

func runSourcePass(
	ctx context.Context,
	state *sourceSessionState,
	connection *pgx.Conn,
	db postgresConnection,
	totalAttempts *uint64,
) error {
	if state == nil {
		return errors.New(
			"FI ingest worker source session state is required",
		)
	}

	config := state.Config
	now := time.Now()

	if !now.Before(state.NextRepair) {
		plan, err := workerRecordedSourcePlan(
			ctx,
			connection,
			config,
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
			"REPAIR PLAN source=%s time=%s mode=%s interval=%s discovered=%d accepted=%d pending=%d conflict=%d ready_notified=%d known_rejected=%d unexpected_pending=%d\n",
			config.SourceID,
			now.Format(time.RFC3339),
			state.Repair.Mode(),
			state.Repair.Interval(),
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
			totalAttempts,
		); err != nil {
			return err
		}

		result := "Clean"

		if !assessment.Clean() {
			result = "Anomaly"
		}

		state.Repair.Observe(
			assessment.Clean(),
		)

		fmt.Printf(
			"REPAIR CADENCE source=%s result=%s mode=%s interval=%s clean_count=%d\n",
			config.SourceID,
			result,
			state.Repair.Mode(),
			state.Repair.Interval(),
			state.Repair.CleanCount(),
		)

		state.NextRepair =
			time.Now().Add(
				state.Repair.Interval(),
			)
	} else {
		plan, markerCount, err :=
			readyPlan(
				ctx,
				config,
				connection,
			)
		if err != nil {
			return err
		}

		fmt.Printf(
			"READY PLAN source=%s time=%s markers=%d accepted=%d pending=%d conflict=%d\n",
			config.SourceID,
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
			totalAttempts,
		); err != nil {
			return err
		}
	}

	retryPlan, dueCount, err :=
		dueRetryPlan(
			ctx,
			config,
			connection,
			now,
		)
	if err != nil {
		return err
	}

	if dueCount == 0 {
		return nil
	}

	fmt.Printf(
		"RETRY PLAN source=%s time=%s due=%d accepted=%d pending=%d conflict=%d\n",
		config.SourceID,
		now.Format(time.RFC3339),
		dueCount,
		retryPlan.Accepted,
		retryPlan.Pending,
		retryPlan.Conflict,
	)

	return processPlan(
		ctx,
		config,
		db,
		retryPlan,
		false,
		totalAttempts,
	)
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

		if err := generationready.RemoveReceiptNamesForSource(
			config.ReadyRoot,
			config.SourceID,
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

	candidates, err := workerDiscoverReceiptNames(
		config,
		names,
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
	names, err := generationready.ReadReceiptNamesForSource(
		config.ReadyRoot,
		config.SourceID,
		config.ReadyBatchSize,
	)
	if err != nil {
		return recordingest.ReconcilePlan{}, 0, err
	}
	if len(names) == 0 {
		return recordingest.ReconcilePlan{}, 0, nil
	}

	candidates, err := workerDiscoverReceiptNames(
		config,
		names,
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
			return &sourceReconcileConflictError{
				Detail:       item.Detail,
				GenerationID: item.Candidate.GenerationID,
				SourceID:     item.Candidate.SourceID,
			}
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
		"  fi-ingest-worker [options]",
	)

	os.Exit(2)
}
