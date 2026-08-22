// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package operation

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

type JournalEvent string

const (
	JournalStarted  JournalEvent = "Started"
	JournalFinished JournalEvent = "Finished"
)

// JournalEntry is one immutable lifecycle entry for a bounded FI operation.
// Started and Finished are separate entries linked by OperationID.
type JournalEntry struct {
	Event       JournalEvent             `json:"event"`
	OperationID string                   `json:"operation_id"`
	ScopeID     string                   `json:"scope_id"`
	Kind        records.OperationKind    `json:"kind"`
	StartedAt   string                   `json:"started_at"`
	FinishedAt  string                   `json:"finished_at,omitempty"`
	Outcome     records.OperationOutcome `json:"outcome,omitempty"`
	ReasonCode  string                   `json:"reason_code,omitempty"`
}

func DefaultJournalPath(scopeID string) (string, error) {
	if !safeScopeID(scopeID) {
		return "", fmt.Errorf("invalid scope id for operation journal filename")
	}
	base := os.Getenv("FI_STATE_DIR")
	if base == "" {
		programData := os.Getenv("ProgramData")
		if programData == "" {
			return "", errors.New("ProgramData is not set")
		}
		base = filepath.Join(programData, "FI", "state")
	}
	return filepath.Join(base, scopeID+"-operations.jsonl"), nil
}

func AppendStarted(path string, started Started) error {
	entry := JournalEntry{
		Event:       JournalStarted,
		OperationID: started.OperationID,
		ScopeID:     started.ScopeID,
		Kind:        started.Kind,
		StartedAt:   started.StartedAt,
	}
	return appendEntry(path, entry)
}

func AppendFinished(path string, record records.OperationRecord) error {
	entry := JournalEntry{
		Event:       JournalFinished,
		OperationID: record.OperationID,
		ScopeID:     record.ScopeID,
		Kind:        record.Kind,
		StartedAt:   record.StartedAt,
		FinishedAt:  record.FinishedAt,
		Outcome:     record.Outcome,
		ReasonCode:  record.ReasonCode,
	}
	return appendEntry(path, entry)
}

// appendEntry writes one validated immutable lifecycle entry as one JSON line and
// flushes it before returning. The journal is FI-owned runtime history; it does
// not alter the governed filesystem being observed.
func appendEntry(path string, entry JournalEntry) error {
	if err := validateJournalEntry(entry); err != nil {
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
	if err := encoder.Encode(entry); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

// ReadAll is intentionally bounded to the caller-selected journal file and is
// used for diagnostics/tests. PostgreSQL will own long-term operational history
// after transport/recorder work exists.
//
// Pre-durable-start terminal records written by the earlier Phase 1 journal core
// are accepted as Finished entries so existing pre-alpha journals remain readable.
func ReadAll(path string) ([]JournalEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	result := make([]JournalEntry, 0)
	scanner := bufio.NewScanner(file)
	buffer := make([]byte, 64*1024)
	scanner.Buffer(buffer, 1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}

		var entry JournalEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			return nil, err
		}

		// Older pre-alpha journal lines were terminal OperationRecord objects
		// without an event field. Treat those as Finished entries.
		if entry.Event == "" && entry.Outcome != "" {
			entry.Event = JournalFinished
		}

		if err := validateJournalEntry(entry); err != nil {
			return nil, err
		}
		result = append(result, entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

// RecoverInterrupted closes any durable Started entries that have no matching
// Finished entry. Recovery is append-only: the original Started entry remains,
// and one Interrupted / ProcessRestart terminal entry is appended for the same
// OperationID. Calling recovery again is idempotent because recovered operations
// now have a terminal entry.
func RecoverInterrupted(path string, scopeID string) ([]records.OperationRecord, error) {
	if !safeScopeID(scopeID) {
		return nil, fmt.Errorf("invalid scope id for operation journal recovery")
	}

	entries, err := ReadAll(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	startedByID := make(map[string]Started)
	finishedByID := make(map[string]JournalEntry)
	startedOrder := make([]string, 0)

	for _, entry := range entries {
		if entry.ScopeID != scopeID {
			return nil, fmt.Errorf("OperationJournalScopeMismatch: %s", entry.OperationID)
		}

		switch entry.Event {
		case JournalStarted:
			if _, exists := startedByID[entry.OperationID]; exists {
				return nil, fmt.Errorf("DuplicateStartedOperation: %s", entry.OperationID)
			}
			startedByID[entry.OperationID] = Started{
				OperationID: entry.OperationID,
				ScopeID:     entry.ScopeID,
				Kind:        entry.Kind,
				StartedAt:   entry.StartedAt,
			}
			startedOrder = append(startedOrder, entry.OperationID)

		case JournalFinished:
			if _, exists := finishedByID[entry.OperationID]; exists {
				return nil, fmt.Errorf("DuplicateFinishedOperation: %s", entry.OperationID)
			}
			finishedByID[entry.OperationID] = entry

			if started, exists := startedByID[entry.OperationID]; exists {
				if entry.ScopeID != started.ScopeID ||
					entry.Kind != started.Kind ||
					entry.StartedAt != started.StartedAt {
					return nil, fmt.Errorf("OperationLifecycleMismatch: %s", entry.OperationID)
				}
			}
		}
	}

	recovered := make([]records.OperationRecord, 0)
	for _, operationID := range startedOrder {
		if _, finished := finishedByID[operationID]; finished {
			continue
		}

		started := startedByID[operationID]
		record, err := started.Finish(records.OperationInterrupted, "ProcessRestart")
		if err != nil {
			return recovered, err
		}
		if err := AppendFinished(path, record); err != nil {
			return recovered, err
		}
		recovered = append(recovered, record)
	}

	return recovered, nil
}

func validateJournalEntry(entry JournalEntry) error {
	switch entry.Event {
	case JournalStarted:
		if entry.FinishedAt != "" {
			return errors.New("StartedEntryHasFinishedAt")
		}
		if entry.Outcome != "" {
			return errors.New("StartedEntryHasOutcome")
		}
		if strings.TrimSpace(entry.ReasonCode) != "" {
			return errors.New("StartedEntryHasReasonCode")
		}

		// Reuse the stable operation-record validator for operation identity,
		// scope, kind, and canonical timestamp validation without creating a
		// second copy of those rules.
		probe := records.OperationRecord{
			OperationID: entry.OperationID,
			ScopeID:     entry.ScopeID,
			Kind:        entry.Kind,
			StartedAt:   entry.StartedAt,
			FinishedAt:  entry.StartedAt,
			Outcome:     records.OperationComplete,
		}
		return records.ValidateOperationRecord(probe)

	case JournalFinished:
		record := records.OperationRecord{
			OperationID: entry.OperationID,
			ScopeID:     entry.ScopeID,
			Kind:        entry.Kind,
			StartedAt:   entry.StartedAt,
			FinishedAt:  entry.FinishedAt,
			Outcome:     entry.Outcome,
			ReasonCode:  entry.ReasonCode,
		}
		return records.ValidateOperationRecord(record)

	default:
		return errors.New("UnsupportedValue: event")
	}
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
