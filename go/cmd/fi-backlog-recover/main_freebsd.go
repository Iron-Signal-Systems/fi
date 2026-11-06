//go:build freebsd

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/recordingest"
	"github.com/jackc/pgx/v5"
)

// Initially constrained to the one known pending signed generation. This
// CLI cannot accept a different source or write an Accepted journal event.
const sourceID = "iss-fs-22a.iss.local"
const generationID = "20261030T000032.061323100Z-3e38b2210771462c"
const expectedRecords uint64 = 15140785
const expectedBatches uint64 = 8399

// Window profiles define separate checkpoint chains. Non-W32 profiles cannot
// reuse W32 markers and must begin against empty isolated private recovery.
func privateWindowLimits(name string) (recordingest.BacklogWindowLimits, error) {
	switch name {
	case "W32":
		return recordingest.BacklogWindowLimits{MaxRecords: 32768, MaxDataBytes: 256 << 20}, nil
	case "W64":
		return recordingest.BacklogWindowLimits{MaxRecords: 65536, MaxDataBytes: 1 << 30}, nil
	case "W96":
		return recordingest.BacklogWindowLimits{MaxRecords: 98304, MaxDataBytes: 1 << 30}, nil
	case "W128":
		return recordingest.BacklogWindowLimits{MaxRecords: 131072, MaxDataBytes: 1 << 30}, nil
	default:
		return recordingest.BacklogWindowLimits{}, errors.New("FI backlog recovery: window-profile must be W32, W64, W96, or W128")
	}
}

// Experimental write modes are a fresh first-window source scan and a
// continuous resume over committed descriptors from the SAME window profile.
func validatePrivateWindowMode(profile string, enable, streamLoader, continuousPrivate, indexedPrivate, preflightOnly bool, startWindow, maxWindows int) error {
	if profile == "W32" {
		return nil // Preserve original W32 mode compatibility.
	}
	if !enable || indexedPrivate || preflightOnly {
		return errors.New("FI non-W32 window profiles require private-writes and forbid indexed/preflight modes")
	}
	if streamLoader && !continuousPrivate && startWindow == 0 && maxWindows == 1 {
		return nil
	}
	if continuousPrivate && !streamLoader && startWindow >= 1 && maxWindows == 0 {
		return nil
	}
	return errors.New("FI non-W32 windows require stream-loader start-window=0 max-windows=1, or continuous-private start-window>=1 max-windows=0")
}

func run() error {
	var fileProfile string

	var source, generation, pg, custody, recorded, private, verifiedCacheRoot string
	var namespaces, enable, streamLoader, indexedPrivate, preflightOnly, continuousPrivate bool
	var privateFieldPartitions bool
	var maxRuntime time.Duration
	var maxWindows, startWindow, processingChunkRecords int
	var testStopAfterWindows, testFieldFailWindow int
	var securityProfile, windowProfile string
	var optimizedK32 bool
	var deferredVerifiedClone bool
	var privateIndexedCounts bool
	var privateThirtyMinuteProbe bool
	var testDeferredFault string
	flag.StringVar(&testDeferredFault,"test-deferred-fault","","EXPERIMENT ONLY: corrupt-clone, after-publish, or kill-after-publish in signed W128/K32 window 3; requires -deferred-verified-clone and -test-stop-after-windows=1")
	flag.BoolVar(&deferredVerifiedClone, "deferred-verified-clone", false, "EXPERIMENT ONLY: W128/K32/P3/F3 verified cache; defer artifact marker until signed SHA and typed SQL verification share one private transaction")
	flag.BoolVar(&privateIndexedCounts, "private-indexed-count-verify", false, "DEV ONLY: use signed-batch indexed LATERAL count/byte verifier in exact isolated deferred-clone W128 experiment")
	flag.BoolVar(&privateThirtyMinuteProbe, "private-30m-probe", false, "DEV ONLY: allow exactly 30m with original count SQL in isolated signed W128 deferred clone (normal 10m limit unchanged)")
	flag.BoolVar(&optimizedK32, "optimized-k32", false, "validated private W128/K32/P3/F3 preset; requires -private-field-partitions and existing verified cache")
	flag.StringVar(&windowProfile, "window-profile", "W32", "PRIVATE recovery window W32=32768/256MiB, W64=65536/1GiB, W96=98304/1GiB, W128=131072/1GiB; checkpoints cannot be mixed")
	flag.IntVar(&processingChunkRecords, "processing-chunk-records", 0, "experimental PRIVATE joined-source and cross-batch typed processing chunks (32768,65536,98304,131072) inside one W128 atomic window; P3/F3 COPY caps remain bounded")
	flag.StringVar(&source, "source", "", "exact original signed FI source")
	flag.StringVar(&generation, "generation-id", "", "exact original signed FI generation")
	flag.StringVar(&pg, "postgres", "", "FI ingest PostgreSQL connection string")
	flag.StringVar(&custody, "custody-root", "/var/db/fi/custody/generation", "original immutable FIGT custody")
	flag.StringVar(&recorded, "recorded-root", "/var/db/fi/custody/recorded", "original immutable recorded receipts")
	flag.StringVar(&private, "private-root", "", "pre-created private 0700 recovery directory")
	flag.StringVar(&verifiedCacheRoot, "verified-cache-root", "", "DEV ONLY: first stream fully authenticates and caches original FIGT; timed W128 resume reads verified cached batches without rescanning custody")
	flag.BoolVar(&namespaces, "source-namespaces", false, "recorded receipt uses per-source directory")
	flag.BoolVar(&enable, "private-writes", false, "explicitly enable PRIVATE recovery writes")
	flag.BoolVar(&streamLoader, "stream-loader", false, "retain only requested window data while streaming and verifying entire signed custody")
	flag.BoolVar(&indexedPrivate, "indexed-private", false, "PRIVATE-ONLY resume from earlier complete validated shadow metadata; partial custody scan is NOT complete transfer verification")
	flag.BoolVar(&preflightOnly, "preflight-only", false, "read-only 10m indexed source preflight; no database writes or checkpoints")
	flag.BoolVar(&continuousPrivate, "continuous-private", false, "single signed custody stream, durable private commits for all remaining windows, full final verification; never Accepted")
	flag.DurationVar(&maxRuntime, "max-runtime", 0, "hard run deadline including extraction and PostgreSQL operations, e.g. 10m")
	flag.StringVar(&fileProfile, "file-profile", "F1", "existing File bulk profile F1/F3")
	flag.StringVar(&securityProfile, "security-profile", "P1", "fixed bounded security source COPY batch: P1 conservative, P3 benchmark candidate; immutable for this invocation")
	flag.IntVar(&maxWindows, "max-windows", 2, "private windows to process per invocation; 0 means to final window")
	flag.IntVar(&startWindow, "start-window", 0, "original signed window index to resume from")
	flag.BoolVar(&privateFieldPartitions, "private-field-partitions", false, "DEV ONLY: field COPY into validated detached partitions in an isolated W128 private database")
	flag.IntVar(&testStopAfterWindows, "test-stop-after-windows", 0, "DEV ONLY: cancel after N durable W128 windows; 0 means normal behavior")
	flag.IntVar(&testFieldFailWindow, "test-field-fail-window", 0, "DEV ONLY: inject late private-field partition rollback in exact window")
	flag.Parse()
	if optimizedK32 {
		// A clean checkout without the validated partition implementation must
		// fail closed. This never changes canonical FI ingest behavior.
		partition := flag.Lookup("private-field-partitions")
		partitionEnabled := partition != nil && partition.Value.String() == "true"
		explicit := make(map[string]string)
		flag.Visit(func(f *flag.Flag) { explicit[f.Name] = f.Value.String() })
		preset, err := selectValidatedK32(explicit, partitionEnabled, enable, continuousPrivate,
			indexedPrivate, streamLoader, preflightOnly, verifiedCacheRoot != "", startWindow, maxWindows)
		if err != nil {
			return err
		}
		windowProfile, processingChunkRecords = preset.WindowProfile, preset.ProcessingChunkRecords
		securityProfile, fileProfile = preset.SecurityProfile, preset.FileProfile
		fmt.Printf("FI VALIDATED PRIVATE PROFILE name=%s outer=%s chunk=%d security=%s file=%s field_partitions=required\n",
			preset.Name, windowProfile, processingChunkRecords, securityProfile, fileProfile)
	}
	if flag.NArg() != 0 || source != sourceID || generation != generationID ||
		pg == "" || private == "" || (!enable && !preflightOnly) || maxWindows < 0 || maxWindows > 1000 || startWindow < 0 {
		return errors.New("exact source/generation, postgres, private-root, private-writes and max-windows 0..1000 required")
	}
	if !filepath.IsAbs(private) || !filepath.IsAbs(custody) || !filepath.IsAbs(recorded) {
		return errors.New("all directories must be absolute")
	}
	for _, p := range []string{private, custody, recorded} {
		info, err := os.Lstat(p)
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("directory is not real: %s", p)
		}
		if p == private && info.Mode().Perm() != 0700 {
			return fmt.Errorf("private root %s must have exact 0700 permissions", p)
		}
	}
	if err := validatePrivateWindowMode(windowProfile, enable, streamLoader, continuousPrivate, indexedPrivate, preflightOnly, startWindow, maxWindows); err != nil {
		return err
	}
	if verifiedCacheRoot != "" {
		if windowProfile != "W128" || !enable ||
			!((streamLoader && startWindow == 0 && maxWindows == 1) ||
				(continuousPrivate && startWindow >= 1 && maxWindows == 0)) {
			return errors.New("verified-cache-root is restricted to W128 signed seed or verified cached continuous private trial")
		}
		if !filepath.IsAbs(verifiedCacheRoot) {
			return errors.New("FI verified cache: absolute root required")
		}
		info, err := os.Lstat(verifiedCacheRoot)
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
			return errors.New("FI verified cache: existing real directory with exactly 0700 required")
		}
	}
	if processingChunkRecords != 0 {
		if windowProfile != "W128" || !continuousPrivate {
			return errors.New("FI processing-chunk-records requires W128 continuous-private; existing paths remain unchanged")
		}
		switch processingChunkRecords {
		case 32768, 65536, 98304, 131072:
		default:
			return errors.New("FI processing-chunk-records must be 32768,65536,98304,131072")
		}
	}
	// The general recovery deadline remains <=10m. The only longer run is
	// explicitly opted-in, isolated signed-cache W128/K32/P3/F3 validation.
	if maxRuntime < 0 || (maxRuntime > 10*time.Minute &&
		!(privateThirtyMinuteProbe && maxRuntime == 30*time.Minute)) {
		return errors.New("max-runtime must be <=10m except explicit private 30m signed probe")
	}
	if preflightOnly && (!indexedPrivate || enable) {
		return errors.New("preflight-only must use indexed-private WITHOUT private-writes")
	}
	if continuousPrivate && (indexedPrivate || streamLoader || preflightOnly || !enable || maxWindows != 0 || startWindow < 1) {
		return errors.New("continuous-private requires private-writes, start-window>0, max-windows=0, no other recovery mode")
	}
	if indexedPrivate && (streamLoader || startWindow == 0 || maxWindows < 1 || maxWindows > 2) {
		return errors.New("indexed-private requires start-window > 0 and one or two selected windows; cannot combine with stream-loader")
	}
	if privateFieldPartitions && (!continuousPrivate || !enable || windowProfile != "W128" ||
		(processingChunkRecords != 32768 && processingChunkRecords != 65536) || verifiedCacheRoot == "" || startWindow < 1 ||
		securityProfile != "P3" || fileProfile != "F3") {
		return errors.New("FI private field partitions require isolated cached W128 continuous-private P3/F3 with 32768 processing chunk")
	}
	if deferredVerifiedClone && (!enable || !continuousPrivate || !privateFieldPartitions ||
		windowProfile != "W128" || processingChunkRecords != 32768 ||
		securityProfile != "P3" || fileProfile != "F3" ||
		verifiedCacheRoot == "" || startWindow != 3 || maxWindows != 0 ||
		indexedPrivate || streamLoader || preflightOnly) {
		return errors.New("FI deferred verified clone requires isolated signed-cache W128/K32/P3/F3 private joined trial starting at window 3")
	}
	if privateThirtyMinuteProbe && (maxRuntime != 30*time.Minute || !deferredVerifiedClone ||
		!enable || !continuousPrivate || !privateFieldPartitions ||
		windowProfile != "W128" || processingChunkRecords != 32768 ||
		securityProfile != "P3" || fileProfile != "F3" ||
		verifiedCacheRoot == "" || startWindow != 3 || maxWindows != 0 ||
		indexedPrivate || privateIndexedCounts || streamLoader || preflightOnly ||
		testDeferredFault != "" || testStopAfterWindows != 0 || testFieldFailWindow != 0) {
		return errors.New("FI 30m probe requires exclusive private deferred signed W128/K32/P3/F3 original-verifier path")
	}
	if privateIndexedCounts && (!deferredVerifiedClone || !enable || !continuousPrivate || startWindow != 3 ||
		windowProfile != "W128" || processingChunkRecords != 32768 || !privateFieldPartitions ||
		securityProfile != "P3" || fileProfile != "F3" || indexedPrivate || preflightOnly || streamLoader) {
		return errors.New("FI indexed count verification requires exact private deferred signed W128/K32/P3/F3 recovery")
	}
	if testDeferredFault != "" && (!deferredVerifiedClone || startWindow != 3 || testStopAfterWindows != 1 ||
		(testDeferredFault != recordingest.DeferredFaultCorruptClone && testDeferredFault != recordingest.DeferredFaultAfterPublish && testDeferredFault != recordingest.DeferredFaultKillAfterPublish)) {
		return errors.New("FI deferred fault injection requires isolated W128/K32 window=3 exact one-window stop")
	}
	if (testStopAfterWindows != 0 && (testStopAfterWindows < 1 || testStopAfterWindows > 2 || !continuousPrivate ||
		windowProfile != "W128" || verifiedCacheRoot == "" || processingChunkRecords != 32768)) ||
		(testFieldFailWindow != 0 && (!privateFieldPartitions || testFieldFailWindow < startWindow ||
			testFieldFailWindow > startWindow+1)) {
		return errors.New("FI isolated field benchmark: illegal test stop/failure combination")
	}
	ctx := context.Background()
	var stop context.CancelFunc
	if maxRuntime > 0 {
		ctx, stop = context.WithTimeout(ctx, maxRuntime)
	} else {
		ctx, stop = context.WithCancel(ctx)
	}
	defer stop()
	if privateFieldPartitions {
		ctx = recordingest.WithPrivateSecurityFieldPartitions(ctx)
	}
	if deferredVerifiedClone {
		ctx = recordingest.WithPrivateDeferredVerifiedClone(ctx)
		fmt.Println("FI DEFERRED VERIFIED CLONE EXPERIMENT on=private-only zfs_clone=required artifact_marker=joined_tx signed_batch_hash=typed_ingest")
	}
	if privateIndexedCounts {
		ctx = recordingest.WithPrivateIndexedWindowCountVerify(ctx)
		fmt.Println("FI PRIVATE INDEXED COUNT VERIFY mode=per_signed_batch_lateral scope=private_only")
	}
	if testDeferredFault != "" {
		var faultErr error
		ctx,faultErr=recordingest.WithPrivateDeferredFault(ctx,testDeferredFault)
		if faultErr!=nil{return faultErr}
		fmt.Printf("FI PRIVATE DEFERRED FAULT ARMED mode=%s window=3\\n",testDeferredFault)
	}
	if testFieldFailWindow != 0 {
		var failErr error
		ctx, failErr = recordingest.WithPrivateSecurityFieldLateFailure(ctx, testFieldFailWindow)
		if failErr != nil {
			return failErr
		}
	}
	if processingChunkRecords != 0 {
		var chunkErr error
		ctx, chunkErr = recordingest.WithBacklogJoinedSourceChunkRecords(ctx, processingChunkRecords)
		if chunkErr != nil {
			return chunkErr
		}
	}
	if securityProfile != "P1" && securityProfile != "P3" {
		return errors.New("FI backlog recovery permits only benchmarked P1/P3 security profiles")
	}
	var profileErr error
	ctx, profileErr = recordingest.WithFixedSecurityBulkProfile(ctx, securityProfile)
	if profileErr != nil {
		return profileErr
	}
	ctx, profileErr = recordingest.WithFixedFileBulkProfile(ctx, fileProfile)
	if profileErr != nil {
		return profileErr
	}
	limits, err := privateWindowLimits(windowProfile)
	if err != nil {
		return err
	}
	fRows, fBytes, oRows, oBytes := recordingest.EffectiveFileBulkLimits(ctx)
	sRows, sBytes := recordingest.EffectiveSecurityBulkLimits(ctx)
	fmt.Printf("FI TUNING EFFECTIVE security_profile=%s security_source_rows=%d security_source_bytes=%d file_profile=%s source_rows=%d source_bytes=%d observation_rows=%d observation_bytes=%d ntfs_prefetch_rows=512\n",
		recordingest.FixedSecurityBulkProfileName(ctx), sRows, sBytes, fileProfile, fRows, fBytes, oRows, oBytes)

	fmt.Printf("FI REAL BACKLOG CONFIG security_profile=%s window_profile=%s max_window_records=%d max_window_data_bytes=%d\n",
		recordingest.FixedSecurityBulkProfileName(ctx), windowProfile, limits.MaxRecords, limits.MaxDataBytes)
	canonical, state, err := recordingest.OpenPostgreSQL(ctx, pg)
	if err != nil {
		return err
	}
	defer canonical.Close(context.Background())
	if state.RelationalTables != 49 {
		return errors.New("FI relational schema is not 49 tables")
	}
	reader, err := pgx.Connect(ctx, pg)
	if err != nil {
		return err
	}
	defer reader.Close(context.Background())
	// Private schemas must already exist with the exact tested grants.
	var ready bool
	if err := canonical.QueryRow(ctx, `
SELECT
 to_regclass('fi_recovery.verified_artifact_window') IS NOT NULL AND
 to_regclass('fi_recovery.pending_source_record') IS NOT NULL AND
 to_regclass('fi_recovery.source_window') IS NOT NULL AND
 to_regclass('fi_recovery.typed_window') IS NOT NULL AND
 to_regclass('fi_recovery_projection.recorded_generation') IS NOT NULL AND
 to_regclass('fi_recovery_projection.source_record') IS NOT NULL AND
 has_table_privilege(current_user,'fi_recovery.typed_window','SELECT') AND
 has_table_privilege(current_user,'fi_recovery.typed_window','INSERT') AND
 NOT has_table_privilege(current_user,'fi_recovery.typed_window','UPDATE,DELETE,TRUNCATE')
`).Scan(&ready); err != nil {
		return fmt.Errorf("FI private schema verification: %w", err)
	}
	if !ready {
		return errors.New("FI private recovery schemas and append-only rights are not installed")
	}
	var already bool
	if err := canonical.QueryRow(ctx, `
SELECT EXISTS(SELECT 1 FROM fi.recorded_generation
WHERE source_id=$1 AND generation_id=$2)
`, source, generation).Scan(&already); err != nil {
		return err
	}
	if already {
		return errors.New("generation already authoritative; private recovery not required")
	}
	// Never mix experimental window checkpoints with the active W32 chain.
	// The first experimental window requires empty private checkpoint and projection tables.
	// Use a separately initialized PostgreSQL instance and artifact root.
	if windowProfile != "W32" && startWindow == 0 {
		var existing bool
		if err := canonical.QueryRow(ctx, `SELECT
 EXISTS (SELECT 1 FROM fi_recovery.verified_artifact_window) OR
 EXISTS (SELECT 1 FROM fi_recovery.source_window) OR
 EXISTS (SELECT 1 FROM fi_recovery.typed_window) OR
 EXISTS (SELECT 1 FROM fi_recovery_projection.recorded_generation)
`).Scan(&existing); err != nil {
			return fmt.Errorf("FI fresh recovery check: %w", err)
		}
		if existing {
			return errors.New("FI experimental window profile requires empty isolated private recovery tables; checkpoint/projection already exists; no data changed")
		}
		files, err := os.ReadDir(private)
		if err != nil {
			return fmt.Errorf("FI experimental private root scan: %w", err)
		}
		if len(files) != 0 {
			return errors.New("FI experimental window requires a new empty private artifact root; no data changed")
		}
	}

	if indexedPrivate {
		fmt.Printf("FI REAL BACKLOG reading authenticated shadow batch index and selected custody prefix source=%s generation=%s; NOT full-transfer validation\n", source, generation)
	} else {
		fmt.Printf("FI REAL BACKLOG loading authenticated custody source=%s generation=%s\n", source, generation)
	}
	loadStarted := time.Now()
	loadConfig := recordingest.GenerationLoadConfig{
		CustodyRoot: custody, RecordedRoot: recorded, SourceID: source, SourceNamespaces: namespaces,
		MaxCanonicalBytes: 68719476736, MaxEncodedBytes: 68719476736, MaxManifestBytes: 1048576,
	}
	if continuousPrivate {
		fmt.Printf("FI REAL BACKLOG CONTINUOUS PRIVATE start_window=%d original_signed_generation=%s processing_chunk_records=%d\n", startWindow, generation, processingChunkRecords)
		began := time.Now()
		lastWindow := startWindow - 1
		var durableThisRun uint64
		var durableThrough uint64
		var completedWindowTime time.Duration
		var lastCheckpointElapsed time.Duration
		var testStopTriggered bool

		progress := func(p recordingest.BacklogContinuousProgress) {
			if p.WindowCommitted >= 0 {
				lastWindow = p.WindowCommitted
				durableThrough = p.RecordsDurable
				durableThisRun += p.WindowRecords
				completedWindowTime += p.WindowDuration
				// Report a successful durable checkpoint's actual completion time,
				// not the eventual 10m timer expiration. No partial window counts.
				lastCheckpointElapsed = time.Since(began)

				fmt.Printf("FI REAL BACKLOG DURABLE window=%d/%d inspected_batches=%d/%d records_through=%d/%d artifact=%s ledger=%s source=%s typed=%s window=%s elapsed=%s\n",
					p.WindowCommitted+1, p.TotalWindows, p.BatchesSeen, p.TotalBatches,
					p.RecordsDurable, expectedRecords,
					p.ArtifactDuration.Round(time.Millisecond), p.LedgerDuration.Round(time.Millisecond),
					p.SourceDuration.Round(time.Millisecond), p.TypedDuration.Round(time.Millisecond),
					p.WindowDuration.Round(time.Millisecond), p.Elapsed.Round(time.Millisecond))
				if testStopAfterWindows > 0 && p.WindowCommitted == startWindow+testStopAfterWindows-1 {
					testStopTriggered = true
					stop()
				}
			} else {
				fmt.Printf("FI REAL BACKLOG CONTINUOUS scanned_batches=%d/%d inspected_records=%d/%d durable_records=%d/%d elapsed=%s\n",
					p.BatchesSeen, p.TotalBatches, p.RecordsInspected, expectedRecords, p.RecordsDurable, expectedRecords, p.Elapsed.Round(time.Millisecond))
			}
		}
		var result recordingest.BacklogGenerationVerification
		if verifiedCacheRoot != "" {
			fmt.Printf("FI REAL BACKLOG VERIFIED CACHE RESUME root=%s; original FIGT archive will not be rescanned\n", verifiedCacheRoot)
			result, err = recordingest.RecoverBacklogContinuousPrivateCached(ctx, reader, canonical, loadConfig,
				generation, limits, private, startWindow, verifiedCacheRoot, progress)
		} else {
			result, err = recordingest.RecoverBacklogContinuousPrivate(ctx, reader, canonical, loadConfig,
				generation, limits, private, startWindow, progress)
		}
		if testStopTriggered && (err == nil || errors.Is(err, context.Canceled)) {
			// The stop request is issued ONLY from the callback after a durable
			// completion marker. Verify it independently with a fresh context;
			// never reinterpret a true ingest error as an intentional stop.
			var markerCount int
			var authoritativeCount int
			checkErr := canonical.QueryRow(context.Background(), `
SELECT (SELECT count(*) FROM fi_recovery.typed_window WHERE window_index >= $1 AND window_index < $2),
       (SELECT count(*) FROM fi.recorded_generation) + (SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted')
`, startWindow, startWindow+testStopAfterWindows).Scan(&markerCount, &authoritativeCount)
			if checkErr != nil || markerCount != testStopAfterWindows || authoritativeCount != 0 ||
				lastWindow != startWindow+testStopAfterWindows-1 {
				return fmt.Errorf("FI controlled stop: marker/SoR mismatch windows=%d authoritative=%d last=%d err=%v",
					markerCount, authoritativeCount, lastWindow, checkErr)
			}
			fmt.Printf("FI PRIVATE EXACT WINDOW STOP start=%d windows=%d last=%d records=%d committed_window_time=%s authoritative=0 accepted=0\n",
				startWindow, testStopAfterWindows, lastWindow, durableThisRun, completedWindowTime.Round(time.Millisecond))
			return nil
		}
		if err != nil {
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				elapsed := time.Since(began)
				wallRate := float64(0)
				checkpointRate := float64(0)
				windowRate := float64(0)
				if elapsed > 0 {
					wallRate = float64(durableThisRun) / elapsed.Seconds()
				}
				if lastCheckpointElapsed > 0 {
					checkpointRate = float64(durableThisRun) / lastCheckpointElapsed.Seconds()
				}
				if completedWindowTime > 0 {
					windowRate = float64(durableThisRun) / completedWindowTime.Seconds()
				}
				stopLabel := "FI TEN MINUTE STOP"
				if privateThirtyMinuteProbe {
					stopLabel = "FI THIRTY MINUTE STOP"
				}
				fmt.Printf("%s elapsed=%s last_window=%d new_durable=%d durable_through=%d throughput=%.1f/sec checkpoint_elapsed=%s checkpoint_rate=%.1f/sec committed_window_time=%s committed_window_rate=%.1f/sec authoritative=0 accepted=0\n",
					stopLabel, elapsed.Round(time.Millisecond), lastWindow, durableThisRun, durableThrough,
					wallRate, lastCheckpointElapsed.Round(time.Millisecond), checkpointRate,
					completedWindowTime.Round(time.Millisecond), windowRate)
				return nil
			}
			return fmt.Errorf("FI continuous private recovery: %w", err)
		}
		if result.Windows <= 0 || result.Records != expectedRecords || result.SourceID != sourceID ||
			result.GenerationID != generationID || result.ReceiptSHA256 == "" {
			return errors.New("FI continuous private: final verification identity/count mismatch")
		}
		fmt.Printf("FI REAL BACKLOG PRIVATE COMPLETE windows=%d records=%d bytes=%d elapsed=%s; NO Accepted journal or authoritative publication\n",
			result.Windows, result.Records, result.DataBytes, time.Since(began).Round(time.Millisecond))
		return nil
	}
	var prepared *recordingest.PreparedGeneration
	if indexedPrivate {
		fmt.Printf("FI REAL BACKLOG INDEXED PRIVATE selective custody prefix start_window=%d count=%d; full FIGT verification deferred to final acceptance\n", startWindow, maxWindows)
		prepared, err = recordingest.LoadIndexedBacklogPrivateWindows(ctx, canonical, loadConfig, generation, limits, startWindow, maxWindows)
	} else if streamLoader {
		if maxWindows < 1 || maxWindows > 8 {
			return errors.New("stream-loader currently requires 1..8 requested windows")
		}
		report := func(p recordingest.BacklogStreamProgress) {
			if p.BatchesSeen == 1 || p.BatchesSeen%128 == 0 || p.BatchesSeen == expectedBatches {
				fmt.Printf("FI REAL BACKLOG STREAM inspected_batches=%d/%d records=%d/%d bytes=%d retained_batches=%d current_window=%d elapsed=%s\n",
					p.BatchesSeen, expectedBatches, p.RecordsSeen, expectedRecords, p.DataBytesSeen,
					p.RetainedBatches, p.WindowIndex, time.Since(loadStarted).Round(time.Millisecond))
			}
		}
		if verifiedCacheRoot != "" {
			fmt.Printf("FI REAL BACKLOG ONE-SCAN CACHE BUILD root=%s; retaining all original signed batch data\n", verifiedCacheRoot)
			prepared, err = recordingest.LoadRecordedGenerationSelectedWindowsCached(
				loadConfig, generation, limits, startWindow, maxWindows, verifiedCacheRoot, report)
		} else {
			prepared, err = recordingest.LoadRecordedGenerationSelectedWindows(
				loadConfig, generation, limits, startWindow, maxWindows, report)
		}
	} else {
		prepared, err = recordingest.LoadRecordedGeneration(loadConfig, generation)
	}
	if err != nil {
		return fmt.Errorf("FI signed custody load: %w", err)
	}
	defer prepared.Close()
	if prepared.Receipt.RecordCount != expectedRecords || prepared.Receipt.BatchCount != expectedBatches ||
		prepared.Receipt.Descriptor.SourceID != source || prepared.Receipt.Descriptor.GenerationID != generation {
		return fmt.Errorf("FI signed receipt does not match target records=%d batches=%d", prepared.Receipt.RecordCount, prepared.Receipt.BatchCount)
	}
	windows, err := recordingest.DescribeBacklogWindows(prepared, limits)
	if err != nil {
		return err
	}
	if indexedPrivate {
		fmt.Printf("FI REAL BACKLOG INDEXED selected prefix hashes match previously authenticated shadow index records=%d batches=%d windows=%d receipt=%s partial_read=%s; NOT full transfer revalidation\n",
			expectedRecords, expectedBatches, len(windows), prepared.ReceiptSHA256, time.Since(loadStarted).Round(time.Millisecond))
	} else {
		fmt.Printf("FI REAL BACKLOG verified signed receipt records=%d batches=%d windows=%d receipt=%s load=%s\n",
			expectedRecords, expectedBatches, len(windows), prepared.ReceiptSHA256, time.Since(loadStarted).Round(time.Millisecond))
	}
	if startWindow >= len(windows) {
		return fmt.Errorf("start window %d outside signed window count %d", startWindow, len(windows))
	}
	end := startWindow + maxWindows
	if maxWindows == 0 || end > len(windows) {
		end = len(windows)
	}
	if indexedPrivate && end == len(windows) {
		return errors.New("indexed-private must not finish generation without complete signed custody revalidation")
	}
	if preflightOnly {
		fmt.Printf("FI REAL BACKLOG PREFLIGHT ONLY selected_windows=%d..%d; no private writes, no accepted record, no authoritative changes\n", startWindow, end-1)
		return nil
	}
	var records uint64
	started := time.Now()
	for i := startWindow; i < end; i++ {
		window := windows[i]
		var times [4]time.Duration
		tick := time.Now()
		if _, err := recordingest.MaterializeBacklogWindow(ctx, prepared, limits, i, private); err != nil {
			return fmt.Errorf("window %d artifact: %w", i, err)
		}
		times[0] = time.Since(tick)
		tick = time.Now()
		if err := recordingest.RecordVerifiedBacklogArtifactWindow(ctx, canonical, prepared, limits, i, private); err != nil {
			return fmt.Errorf("window %d artifact ledger: %w", i, err)
		}
		times[1] = time.Since(tick)
		tick = time.Now()
		if err := recordingest.StageVerifiedBacklogSourceWindow(ctx, canonical, prepared, limits, i, private); err != nil {
			return fmt.Errorf("window %d source: %w", i, err)
		}
		times[2] = time.Since(tick)
		tick = time.Now()
		if err := recordingest.StageBacklogTypedWindow(ctx, reader, canonical, prepared, limits, i, private); err != nil {
			return fmt.Errorf("window %d typed: %w", i, err)
		}
		times[3] = time.Since(tick)
		records = window.EndRecord
		fmt.Printf("FI REAL BACKLOG DURABLE window=%d/%d batches=%d..%d records=%d..%d artifact=%s ledger=%s source=%s typed=%s elapsed=%s\n",
			i+1, len(windows), window.StartBatch, window.EndBatch, window.StartRecord, window.EndRecord,
			times[0].Round(time.Millisecond), times[1].Round(time.Millisecond), times[2].Round(time.Millisecond),
			times[3].Round(time.Millisecond), time.Since(started).Round(time.Millisecond))
	}
	if end == len(windows) {
		verified, err := recordingest.VerifyCompleteBacklogTypedGeneration(ctx, reader, prepared, limits)
		if err != nil {
			return fmt.Errorf("FI whole-generation private verification: %w", err)
		}
		fmt.Printf("FI REAL BACKLOG PRIVATE COMPLETE windows=%d records=%d bytes=%d\n", verified.Windows, verified.Records, verified.DataBytes)
	} else {
		fmt.Printf("FI REAL BACKLOG PAUSED completed_to_window=%d durable_records_through=%d/%d; no Accepted journal or authoritative writes\n",
			end, records, expectedRecords)
	}
	if strings.TrimSpace(prepared.ReceiptSHA256) == "" {
		return errors.New("missing receipt")
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
}
