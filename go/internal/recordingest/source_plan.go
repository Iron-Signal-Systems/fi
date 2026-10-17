// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// SourceReceiptDiscoveryError identifies a discovery failure that is
// attributable to one authoritative source namespace.
// It does not classify PostgreSQL failures as source-local.
type SourceReceiptDiscoveryError struct {
	SourceID string
	Cause    error
}

func (e *SourceReceiptDiscoveryError) Error() string {
	return fmt.Sprintf(
		"FI source %q authoritative receipt discovery failed: %v",
		e.SourceID,
		e.Cause,
	)
}

func (e *SourceReceiptDiscoveryError) Unwrap() error {
	return e.Cause
}

// PlanRecordedGenerationsForSource reconciles exactly one source's
// authoritative namespace. Discovery failures retain source attribution;
// relational query failures remain global errors.
func PlanRecordedGenerationsForSource(
	ctx context.Context,
	connection *pgx.Conn,
	recordedRoot string,
	sourceID string,
) (ReconcilePlan, error) {
	if ctx == nil {
		return ReconcilePlan{},
			errors.New("FI source reconciliation context is required")
	}

	if connection == nil {
		return ReconcilePlan{},
			errors.New("FI source reconciliation PostgreSQL connection is required")
	}

	if strings.TrimSpace(sourceID) == "" {
		return ReconcilePlan{},
			errors.New("FI source reconciliation source ID is required")
	}

	candidates, err := DiscoverRecordedReceiptsForSource(
		recordedRoot,
		sourceID,
	)
	if err != nil {
		return ReconcilePlan{}, &SourceReceiptDiscoveryError{
			SourceID: sourceID,
			Cause:    err,
		}
	}

	return PlanRecordedReceiptCandidatesForIngest(
		ctx,
		connection,
		sourceID,
		candidates,
	)
}
