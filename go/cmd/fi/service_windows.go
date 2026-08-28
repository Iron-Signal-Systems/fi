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
	Version                   string `json:"version"`
	RecordKind                string `json:"record_kind"`
	ObservedAt                string `json:"observed_at"`
	CollectionInterval        string `json:"collection_interval,omitempty"`
	SupportingRefreshInterval string `json:"supporting_refresh_interval,omitempty"`
	Outcome                   string `json:"outcome,omitempty"`
	ConfiguredRoots           int    `json:"configured_roots,omitempty"`
	CompletedRoots            int    `json:"completed_roots,omitempty"`
	PartialRoots              int    `json:"partial_roots,omitempty"`
	FailedRoots               int    `json:"failed_roots,omitempty"`
	SupportingRefreshStatus   string `json:"supporting_refresh_status,omitempty"`
	Error                     string `json:"error,omitempty"`
}

type serviceCollectorFunc func(context.Context) (configuredRunSummary, error)
type serviceSupportingRefreshFunc func(context.Context) (supportingSourceRefreshSummary, error)
type serviceAppendRecordFunc func(serviceRuntimeRecord) error

type fiWindowsService struct {
	collectionInterval        time.Duration
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
	collectionInterval time.Duration,
	supportingRefreshInterval time.Duration,
) error {
	if collectionInterval <= 0 {
		return errors.New("service collection interval must be greater than zero")
	}
	if supportingRefreshInterval <= 0 {
		return errors.New("service supporting-refresh interval must be greater than zero")
	}

	return svc.Run(
		windowsServiceName,
		&fiWindowsService{
			collectionInterval:        collectionInterval,
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- runServiceLoop(
			ctx,
			service.collectionInterval,
			service.supportingRefreshInterval,
			writeConfiguredCollector,
			writeSupportingSourceRefresh,
			appendServiceRuntimeRecord,
		)
	}()

	runningStatus := svc.Status{
		State:   svc.Running,
		Accepts: svc.AcceptStop | svc.AcceptShutdown,
	}
	statuses <- runningStatus

	for {
		select {
		case err := <-done:
			statuses <- svc.Status{State: svc.StopPending}
			if err != nil {
				return false, 1
			}
			return false, 0

		case request, ok := <-requests:
			if !ok {
				statuses <- svc.Status{State: svc.StopPending}
				cancel()
				err := <-done
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
				cancel()
				err := <-done
				if err != nil {
					return false, 1
				}
				return false, 0
			}
		}
	}
}

func runServiceLoop(
	ctx context.Context,
	collectionInterval time.Duration,
	supportingRefreshInterval time.Duration,
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
	if collect == nil || refresh == nil || appendRecord == nil {
		return errors.New("service runtime dependency is nil")
	}

	if err := appendRecord(serviceRuntimeRecord{
		Version:                   serviceRuntimeVersion,
		RecordKind:                "ServiceStarted",
		ObservedAt:                serviceNow(),
		CollectionInterval:        collectionInterval.String(),
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
	if record.Version != serviceRuntimeVersion {
		return errors.New("invalid service runtime record version")
	}
	if record.RecordKind == "" || record.ObservedAt == "" {
		return errors.New("invalid service runtime record")
	}

	path, err := serviceRuntimeLogPath()
	if err != nil {
		return err
	}
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
