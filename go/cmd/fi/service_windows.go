// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
	"golang.org/x/sys/windows/svc"
)

const (
	windowsServiceName        = "FICollector"
	serviceRuntimeVersion     = "fi-service-runtime/0.1"
	serviceRuntimeLogName     = "service-runtime.jsonl"
	serviceTimestampLayout    = "2006-01-02T15:04:05.000000000Z"
	serviceOutcomeComplete    = "Complete"
	serviceOutcomePartial     = "Partial"
	serviceOutcomeFailed      = "Failed"
	serviceOutcomeInterrupted = "Interrupted"
)

type serviceRuntimeRecord struct {
	Version                    string `json:"version"`
	RecordKind                 string `json:"record_kind"`
	ObservedAt                 string `json:"observed_at"`
	CollectionInterval         string `json:"collection_interval,omitempty"`
	USNInterval                string `json:"usn_interval,omitempty"`
	SecurityInterval           string `json:"security_interval,omitempty"`
	SupportingRefreshInterval  string `json:"supporting_refresh_interval,omitempty"`
	Outcome                    string `json:"outcome,omitempty"`
	ConfiguredRoots            int    `json:"configured_roots,omitempty"`
	CompletedRoots             int    `json:"completed_roots,omitempty"`
	PartialRoots               int    `json:"partial_roots,omitempty"`
	SkippedRoots               int    `json:"skipped_roots,omitempty"`
	FailedRoots                int    `json:"failed_roots,omitempty"`
	SupportingRefreshStatus    string `json:"supporting_refresh_status,omitempty"`
	SecurityReadWindows        int    `json:"security_read_windows,omitempty"`
	SecuritySourceMatches      int    `json:"security_source_matching_events,omitempty"`
	SecuritySelectedEvents     int    `json:"security_selected_events,omitempty"`
	SecurityIgnoredEvents      int    `json:"security_ignored_events,omitempty"`
	SecurityVerifiedBatches    int    `json:"security_verified_batches,omitempty"`
	SecurityCheckpointAdvanced bool   `json:"security_checkpoint_advanced,omitempty"`
	SecurityCheckpointRebased  bool   `json:"security_checkpoint_reinitialized,omitempty"`
	SecurityContinuityGap      bool   `json:"security_continuity_gap,omitempty"`
	SecurityMoreAvailable      bool   `json:"security_more_available,omitempty"`
	Error                      string `json:"error,omitempty"`
}

type serviceStartupRecoveryFunc func() error
type serviceCollectorFunc func(context.Context) (configuredRunSummary, error)
type serviceSupportingRefreshFunc func(context.Context) (supportingSourceRefreshSummary, error)
type serviceAppendRecordFunc func(serviceRuntimeRecord) error

type fiWindowsService struct {
	operationalSnapshot       serviceOperationalSnapshot
	collectionInterval        time.Duration
	usnInterval               time.Duration
	securityInterval          time.Duration
	supportingRefreshInterval time.Duration
}

func parseServiceInterval(name string, value string) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, fmt.Errorf("%s is required", name)
	}

	interval, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", name, err)
	}
	if interval <= 0 {
		return 0, fmt.Errorf("%s must be greater than zero", name)
	}
	return interval, nil
}

func runWindowsService(
	operationalSnapshot serviceOperationalSnapshot,
	collectionInterval time.Duration,
	supportingRefreshInterval time.Duration,
) error {
	if collectionInterval <= 0 {
		return errors.New("service collection interval must be greater than zero")
	}
	if supportingRefreshInterval <= 0 {
		return errors.New("service supporting-refresh interval must be greater than zero")
	}

	usnInterval, err := resolveServiceUSNInterval(operationalSnapshot.USNInterval)
	if err != nil {
		return err
	}
	securityInterval, err := resolveServiceWindowsSecurityInterval(operationalSnapshot.WindowsSecurityInterval)
	if err != nil {
		return err
	}

	return svc.Run(
		windowsServiceName,
		&fiWindowsService{
			operationalSnapshot:       operationalSnapshot,
			collectionInterval:        collectionInterval,
			usnInterval:               usnInterval,
			securityInterval:          securityInterval,
			supportingRefreshInterval: supportingRefreshInterval,
		},
	)
}

func (service *fiWindowsService) Execute(
	_ []string,
	requests <-chan svc.ChangeRequest,
	statuses chan<- svc.Status,
) (bool, uint32) {
	statuses <- svc.Status{State: svc.StartPending}

	// Startup recovery must finish before any independently scheduled writer is
	// allowed to publish. After this boundary, each worker owns its own source
	// checkpoint and the shared spool publication boundary arbitrates publishing.
	if err := recoverServiceSpoolPublications(); err != nil {
		return false, 1
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const workerCount = 3
	done := make(chan error, workerCount)

	appendRecord := func(record serviceRuntimeRecord) error {
		return appendServiceRuntimeRecordAt(
			service.operationalSnapshot.StateDir,
			record,
		)
	}

	go func() {
		done <- runServiceLoop(
			ctx,
			service.collectionInterval,
			service.supportingRefreshInterval,
			func() error { return nil },
			func(ctx context.Context) (configuredRunSummary, error) {
				return writeServiceRootCollector(
					ctx,
					service.operationalSnapshot,
				)
			},
			writeSupportingSourceRefresh,
			appendRecord,
		)
	}()

	go func() {
		done <- runServiceUSNLoop(
			ctx,
			service.usnInterval,
			func(ctx context.Context) (serviceUSNCatchUpSummary, error) {
				return writeServiceUSNCatchUp(
					ctx,
					service.operationalSnapshot,
				)
			},
			appendRecord,
		)
	}()

	go func() {
		done <- runServiceWindowsSecurityLoop(
			ctx,
			service.securityInterval,
			liveServiceWindowsSecuritySource{operationalSnapshot: service.operationalSnapshot},
			appendRecord,
		)
	}()

	runningStatus := svc.Status{
		State:   svc.Running,
		Accepts: svc.AcceptStop | svc.AcceptShutdown,
	}
	statuses <- runningStatus

	waitForWorkers := func(first error, received int) error {
		cancel()
		errs := make([]error, 0, workerCount)
		if received > 0 {
			errs = append(errs, first)
		}
		for index := received; index < workerCount; index++ {
			errs = append(errs, <-done)
		}
		return errors.Join(errs...)
	}

	for {
		select {
		case err := <-done:
			statuses <- svc.Status{State: svc.StopPending}
			err = waitForWorkers(err, 1)
			if err != nil {
				return false, 1
			}
			return false, 0

		case request, ok := <-requests:
			if !ok {
				statuses <- svc.Status{State: svc.StopPending}
				err := waitForWorkers(nil, 0)
				if err != nil {
					return false, 1
				}
				return false, 0
			}

			switch request.Cmd {
			case svc.Interrogate:
				statuses <- runningStatus

			case svc.Stop, svc.Shutdown:
				statuses <- svc.Status{State: svc.StopPending}
				err := waitForWorkers(nil, 0)
				if err != nil {
					return false, 1
				}
				return false, 0
			}
		}
	}
}

func recoverServiceSpoolPublications() error {
	spoolDir, err := spool.DefaultDir()
	if err != nil {
		return fmt.Errorf(
			"resolve FI spool directory for service startup recovery: %w",
			err,
		)
	}

	if _, err := spool.RecoverAbandonedPublications(spoolDir); err != nil {
		return fmt.Errorf(
			"recover FI spool publications at service startup: %w",
			err,
		)
	}

	return nil
}

func runServiceLoop(
	ctx context.Context,
	collectionInterval time.Duration,
	supportingRefreshInterval time.Duration,
	recoverStartup serviceStartupRecoveryFunc,
	collect serviceCollectorFunc,
	refresh serviceSupportingRefreshFunc,
	appendRecord serviceAppendRecordFunc,
) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if collectionInterval <= 0 || supportingRefreshInterval <= 0 {
		return errors.New("service intervals must be greater than zero")
	}
	if recoverStartup == nil ||
		collect == nil ||
		refresh == nil ||
		appendRecord == nil {
		return errors.New("service runtime dependency is nil")
	}

	if err := recoverStartup(); err != nil {
		return fmt.Errorf(
			"FI service startup recovery failed: %w",
			err,
		)
	}

	if err := appendRecord(serviceRuntimeRecord{
		Version:                   serviceRuntimeVersion,
		RecordKind:                "ServiceStarted",
		ObservedAt:                serviceNow(),
		CollectionInterval:        collectionInterval.String(),
		USNInterval:               currentServiceUSNInterval(),
		SecurityInterval:          currentServiceWindowsSecurityInterval(),
		SupportingRefreshInterval: supportingRefreshInterval.String(),
	}); err != nil {
		return err
	}

	if err := runConfiguredServiceCycle(ctx, collect, appendRecord); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return appendServiceStopped(appendRecord)
	}

	collectionTimer := time.NewTimer(collectionInterval)
	supportingRefreshTimer := time.NewTimer(supportingRefreshInterval)
	defer collectionTimer.Stop()
	defer supportingRefreshTimer.Stop()

	for {
		select {
		case <-ctx.Done():
			return appendServiceStopped(appendRecord)

		case <-collectionTimer.C:
			if err := runConfiguredServiceCycle(ctx, collect, appendRecord); err != nil {
				return err
			}
			if ctx.Err() != nil {
				return appendServiceStopped(appendRecord)
			}
			collectionTimer.Reset(collectionInterval)

		case <-supportingRefreshTimer.C:
			if err := runSupportingRefreshServiceCycle(ctx, refresh, appendRecord); err != nil {
				return err
			}
			if ctx.Err() != nil {
				return appendServiceStopped(appendRecord)
			}
			supportingRefreshTimer.Reset(supportingRefreshInterval)
		}
	}
}

func runConfiguredServiceCycle(
	ctx context.Context,
	collect serviceCollectorFunc,
	appendRecord serviceAppendRecordFunc,
) error {
	summary, collectionErr := collect(ctx)

	outcome := serviceOutcomePartial
	switch {
	case collectionErr != nil && errors.Is(collectionErr, context.Canceled) && ctx.Err() != nil:
		outcome = serviceOutcomeInterrupted
	case collectionErr != nil:
		outcome = serviceOutcomeFailed
	case summary.Complete:
		outcome = serviceOutcomeComplete
	}

	record := serviceRuntimeRecord{
		Version:         serviceRuntimeVersion,
		RecordKind:      "ConfiguredCollection",
		ObservedAt:      serviceNow(),
		Outcome:         outcome,
		ConfiguredRoots: summary.ConfiguredRoots,
		CompletedRoots:  summary.CompletedRoots,
		PartialRoots:    summary.PartialRoots,
		FailedRoots:     summary.FailedRoots,
	}
	if collectionErr != nil {
		record.Error = collectionErr.Error()
	}

	return appendRecord(record)
}

func runSupportingRefreshServiceCycle(
	ctx context.Context,
	refresh serviceSupportingRefreshFunc,
	appendRecord serviceAppendRecordFunc,
) error {
	summary, refreshErr := refresh(ctx)

	outcome := string(summary.Status)
	switch {
	case refreshErr != nil && errors.Is(refreshErr, context.Canceled) && ctx.Err() != nil:
		outcome = serviceOutcomeInterrupted
	case refreshErr != nil:
		outcome = serviceOutcomeFailed
	case outcome == "":
		outcome = serviceOutcomePartial
	}

	record := serviceRuntimeRecord{
		Version:                 serviceRuntimeVersion,
		RecordKind:              "SupportingSourceRefresh",
		ObservedAt:              serviceNow(),
		Outcome:                 outcome,
		SupportingRefreshStatus: string(summary.Status),
	}
	if refreshErr != nil {
		record.Error = refreshErr.Error()
	}

	return appendRecord(record)
}

func appendServiceStopped(appendRecord serviceAppendRecordFunc) error {
	return appendRecord(serviceRuntimeRecord{
		Version:    serviceRuntimeVersion,
		RecordKind: "ServiceStopped",
		ObservedAt: serviceNow(),
	})
}

func appendServiceRuntimeRecord(record serviceRuntimeRecord) error {
	path, err := serviceRuntimeLogPath()
	if err != nil {
		return err
	}
	return appendServiceRuntimeRecordAt(filepath.Dir(path), record)
}

func appendServiceRuntimeRecordAt(stateDir string, record serviceRuntimeRecord) error {
	serviceRuntimeLogMu.Lock()
	defer serviceRuntimeLogMu.Unlock()

	if record.Version != serviceRuntimeVersion {
		return errors.New("invalid service runtime record version")
	}
	if record.RecordKind == "" || record.ObservedAt == "" {
		return errors.New("invalid service runtime record")
	}
	if strings.TrimSpace(stateDir) == "" {
		return errors.New("service runtime state directory is required")
	}

	path := filepath.Join(stateDir, serviceRuntimeLogName)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(file)
	if err := encoder.Encode(record); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func serviceRuntimeLogPath() (string, error) {
	base := os.Getenv("FI_STATE_DIR")
	if base == "" {
		programData := os.Getenv("ProgramData")
		if programData == "" {
			return "", errors.New("ProgramData is not set")
		}
		base = filepath.Join(programData, "FI", "state")
	}
	return filepath.Join(base, serviceRuntimeLogName), nil
}

func serviceNow() string {
	return time.Now().UTC().Format(serviceTimestampLayout)
}
