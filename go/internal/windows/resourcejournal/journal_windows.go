// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package resourcejournal

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/process"
)

const (
	timestampLayout = "2006-01-02T15:04:05.000000000Z"
	sampleInterval  = 5 * time.Second
)

type RecordKind string

const (
	ResourceSample  RecordKind = "ResourceSample"
	ResourceSummary RecordKind = "ResourceSummary"
)

// Record is one immutable FI process-resource observation correlated to one
// bounded FI operation by OperationID. CPU and I/O values are deltas since
// resource tracking began for that operation. RAM values are process state at
// the sample time plus the highest values sampled during the operation.
type Record struct {
	RecordKind                 RecordKind            `json:"record_kind"`
	OperationID                string                `json:"operation_id"`
	ScopeID                    string                `json:"scope_id"`
	OperationKind              records.OperationKind `json:"operation_kind"`
	ObservedAt                 string                `json:"observed_at"`
	Elapsed100Nanoseconds      string                `json:"elapsed_100ns"`
	CPU100Nanoseconds          string                `json:"cpu_100ns"`
	WorkingSetBytes            string                `json:"working_set_bytes"`
	PrivateBytes               string                `json:"private_bytes"`
	PeakWorkingSetBytes        string                `json:"peak_working_set_bytes"`
	PeakPrivateBytes           string                `json:"peak_private_bytes"`
	ReadOperations             string                `json:"read_operations"`
	ReadBytes                  string                `json:"read_bytes"`
	WriteOperations            string                `json:"write_operations"`
	WriteBytes                 string                `json:"write_bytes"`
	OtherOperations            string                `json:"other_operations"`
	OtherBytes                 string                `json:"other_bytes"`
	SampleIntervalMilliseconds string                `json:"sample_interval_ms"`
}

// Tracker samples FI process resource usage for one bounded operation. It keeps
// the periodic sampling loop in memory and writes compact immutable observations
// to the separate resource journal.
type Tracker struct {
	path        string
	operationID string
	scopeID     string
	kind        records.OperationKind
	startedAt   time.Time
	start       process.Snapshot
	peakWorking uint64
	peakPrivate uint64
	stop        chan struct{}
	done        chan struct{}
	stopOnce    sync.Once
	mu          sync.Mutex
	sampleErr   error
}

func DefaultPath(scopeID string) (string, error) {
	if !safeScopeID(scopeID) {
		return "", fmt.Errorf("invalid scope id for resource journal filename")
	}
	base := os.Getenv("FI_STATE_DIR")
	if base == "" {
		programData := os.Getenv("ProgramData")
		if programData == "" {
			return "", errors.New("ProgramData is not set")
		}
		base = filepath.Join(programData, "FI", "state")
	}
	return filepath.Join(base, scopeID+"-resources.jsonl"), nil
}

// Start begins resource tracking for one operation. It immediately records one
// ResourceSample, then records another sample every five seconds until Finish.
func Start(
	path string,
	operationID string,
	scopeID string,
	kind records.OperationKind,
) (*Tracker, error) {
	if err := validateOperationIdentity(operationID, scopeID, kind); err != nil {
		return nil, err
	}

	snapshot, err := process.Current()
	if err != nil {
		return nil, err
	}

	tracker := &Tracker{
		path:        path,
		operationID: operationID,
		scopeID:     scopeID,
		kind:        kind,
		startedAt:   time.Now().UTC(),
		start:       snapshot,
		peakWorking: snapshot.WorkingSetBytes,
		peakPrivate: snapshot.PrivateBytes,
		stop:        make(chan struct{}),
		done:        make(chan struct{}),
	}

	if err := tracker.appendSnapshot(ResourceSample, snapshot, tracker.startedAt); err != nil {
		return nil, err
	}

	go tracker.sampleLoop()
	return tracker, nil
}

// Finish stops periodic sampling, captures a final process snapshot, and writes
// one ResourceSummary for the operation.
func (tracker *Tracker) Finish() error {
	tracker.stopOnce.Do(func() {
		close(tracker.stop)
	})
	<-tracker.done

	finalSnapshot, finalErr := process.Current()
	if finalErr == nil {
		finalErr = tracker.appendSnapshot(ResourceSummary, finalSnapshot, time.Now().UTC())
	}

	tracker.mu.Lock()
	sampleErr := tracker.sampleErr
	tracker.mu.Unlock()

	return errors.Join(sampleErr, finalErr)
}

func (tracker *Tracker) sampleLoop() {
	defer close(tracker.done)

	ticker := time.NewTicker(sampleInterval)
	defer ticker.Stop()

	for {
		select {
		case observedAt := <-ticker.C:
			snapshot, err := process.Current()
			if err == nil {
				err = tracker.appendSnapshot(ResourceSample, snapshot, observedAt.UTC())
			}
			if err != nil {
				tracker.mu.Lock()
				if tracker.sampleErr == nil {
					tracker.sampleErr = err
				}
				tracker.mu.Unlock()
				return
			}

		case <-tracker.stop:
			return
		}
	}
}

func (tracker *Tracker) appendSnapshot(
	kind RecordKind,
	snapshot process.Snapshot,
	observedAt time.Time,
) error {
	tracker.mu.Lock()
	if snapshot.WorkingSetBytes > tracker.peakWorking {
		tracker.peakWorking = snapshot.WorkingSetBytes
	}
	if snapshot.PrivateBytes > tracker.peakPrivate {
		tracker.peakPrivate = snapshot.PrivateBytes
	}
	peakWorking := tracker.peakWorking
	peakPrivate := tracker.peakPrivate
	tracker.mu.Unlock()

	record := Record{
		RecordKind:                 kind,
		OperationID:                tracker.operationID,
		ScopeID:                    tracker.scopeID,
		OperationKind:              tracker.kind,
		ObservedAt:                 observedAt.Format(timestampLayout),
		Elapsed100Nanoseconds:      uintString(duration100Nanoseconds(observedAt.Sub(tracker.startedAt))),
		CPU100Nanoseconds:          uintString(delta(snapshot.CPU100Nanoseconds, tracker.start.CPU100Nanoseconds)),
		WorkingSetBytes:            uintString(snapshot.WorkingSetBytes),
		PrivateBytes:               uintString(snapshot.PrivateBytes),
		PeakWorkingSetBytes:        uintString(peakWorking),
		PeakPrivateBytes:           uintString(peakPrivate),
		ReadOperations:             uintString(delta(snapshot.ReadOperationCount, tracker.start.ReadOperationCount)),
		ReadBytes:                  uintString(delta(snapshot.ReadTransferBytes, tracker.start.ReadTransferBytes)),
		WriteOperations:            uintString(delta(snapshot.WriteOperationCount, tracker.start.WriteOperationCount)),
		WriteBytes:                 uintString(delta(snapshot.WriteTransferBytes, tracker.start.WriteTransferBytes)),
		OtherOperations:            uintString(delta(snapshot.OtherOperationCount, tracker.start.OtherOperationCount)),
		OtherBytes:                 uintString(delta(snapshot.OtherTransferBytes, tracker.start.OtherTransferBytes)),
		SampleIntervalMilliseconds: uintString(uint64(sampleInterval / time.Millisecond)),
	}
	return appendRecord(tracker.path, record)
}

func appendRecord(path string, record Record) error {
	if err := validateRecord(record); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
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

// ReadAll reads and validates one resource journal. It is intended for tests and
// diagnostics; PostgreSQL will own long-term resource history after transport.
func ReadAll(path string) ([]Record, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	result := make([]Record, 0)
	scanner := bufio.NewScanner(file)
	buffer := make([]byte, 64*1024)
	scanner.Buffer(buffer, 1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		var record Record
		if err := json.Unmarshal(line, &record); err != nil {
			return nil, err
		}
		if err := validateRecord(record); err != nil {
			return nil, err
		}
		result = append(result, record)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func validateRecord(record Record) error {
	switch record.RecordKind {
	case ResourceSample, ResourceSummary:
	default:
		return errors.New("UnsupportedValue: record_kind")
	}
	if err := validateOperationIdentity(record.OperationID, record.ScopeID, record.OperationKind); err != nil {
		return err
	}
	if _, err := time.Parse(timestampLayout, record.ObservedAt); err != nil {
		return errors.New("InvalidTimestamp: observed_at")
	}

	for name, value := range map[string]string{
		"elapsed_100ns":          record.Elapsed100Nanoseconds,
		"cpu_100ns":              record.CPU100Nanoseconds,
		"working_set_bytes":      record.WorkingSetBytes,
		"private_bytes":          record.PrivateBytes,
		"peak_working_set_bytes": record.PeakWorkingSetBytes,
		"peak_private_bytes":     record.PeakPrivateBytes,
		"read_operations":        record.ReadOperations,
		"read_bytes":             record.ReadBytes,
		"write_operations":       record.WriteOperations,
		"write_bytes":            record.WriteBytes,
		"other_operations":       record.OtherOperations,
		"other_bytes":            record.OtherBytes,
		"sample_interval_ms":     record.SampleIntervalMilliseconds,
	} {
		if value == "" {
			return fmt.Errorf("Required: %s", name)
		}
		if _, err := strconv.ParseUint(value, 10, 64); err != nil {
			return fmt.Errorf("InvalidUnsignedInteger: %s", name)
		}
	}
	return nil
}

func validateOperationIdentity(
	operationID string,
	scopeID string,
	kind records.OperationKind,
) error {
	const probeTime = "2026-01-01T00:00:00.000000000Z"
	probe := records.OperationRecord{
		OperationID: operationID,
		ScopeID:     scopeID,
		Kind:        kind,
		StartedAt:   probeTime,
		FinishedAt:  probeTime,
		Outcome:     records.OperationComplete,
	}
	return records.ValidateOperationRecord(probe)
}

func delta(current uint64, start uint64) uint64 {
	if current < start {
		return 0
	}
	return current - start
}

func duration100Nanoseconds(value time.Duration) uint64 {
	if value <= 0 {
		return 0
	}
	return uint64(value / (100 * time.Nanosecond))
}

func uintString(value uint64) string {
	return strconv.FormatUint(value, 10)
}

func safeScopeID(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			continue
		}
		return false
	}
	return !strings.HasPrefix(value, ".")
}
