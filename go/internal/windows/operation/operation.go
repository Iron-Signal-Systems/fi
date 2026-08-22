// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package operation

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

const timestampLayout = "2006-01-02T15:04:05.000000000Z"

// Started is the immutable identity/start boundary for one FI operation.
type Started struct {
	OperationID string
	ScopeID     string
	Kind        records.OperationKind
	StartedAt   string
}

func Start(scopeID string, kind records.OperationKind) (Started, error) {
	if strings.TrimSpace(scopeID) == "" {
		return Started{}, errors.New("scope id is required")
	}
	operationID, err := newOperationID()
	if err != nil {
		return Started{}, err
	}
	value := Started{
		OperationID: operationID,
		ScopeID:     scopeID,
		Kind:        kind,
		StartedAt:   canonicalNow(),
	}

	// Validate the supplied kind using a temporary complete record. This keeps
	// operation-kind validation in the records package rather than duplicating it.
	probe := records.OperationRecord{
		OperationID: value.OperationID,
		ScopeID:     value.ScopeID,
		Kind:        value.Kind,
		StartedAt:   value.StartedAt,
		FinishedAt:  value.StartedAt,
		Outcome:     records.OperationComplete,
	}
	if err := records.ValidateOperationRecord(probe); err != nil {
		return Started{}, err
	}
	return value, nil
}

func (value Started) Finish(
	outcome records.OperationOutcome,
	reasonCode string,
) (records.OperationRecord, error) {
	record := records.OperationRecord{
		OperationID: value.OperationID,
		ScopeID:     value.ScopeID,
		Kind:        value.Kind,
		StartedAt:   value.StartedAt,
		FinishedAt:  canonicalNow(),
		Outcome:     outcome,
		ReasonCode:  reasonCode,
	}
	if err := records.ValidateOperationRecord(record); err != nil {
		return records.OperationRecord{}, err
	}
	return record, nil
}

func newOperationID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return "op-" + hex.EncodeToString(raw[:]), nil
}

func canonicalNow() string {
	return time.Now().UTC().Format(timestampLayout)
}
