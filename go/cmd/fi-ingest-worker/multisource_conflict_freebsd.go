// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/Iron-Signal-Systems/fi/go/internal/recordingest"
)

type sourceReconcileConflictError struct {
	Detail       string
	GenerationID string
	SourceID     string
}

func (value *sourceReconcileConflictError) Error() string {
	return fmt.Sprintf(
		"FI relational reconcile conflict for source=%q generation=%q: %s",
		value.SourceID,
		value.GenerationID,
		value.Detail,
	)
}

// quarantineSourceConflict isolates only a confirmed source-specific
// relational conflict. All other failures remain fatal to the session.
func quarantineSourceConflict(
	state *sourceSessionState,
	err error,
) error {
	if err == nil {
		return nil
	}
	if state == nil {
		return fmt.Errorf(
			"FI ingest source state is required: %w",
			err,
		)
	}

	var discovery *recordingest.SourceReceiptDiscoveryError
	if errors.As(err, &discovery) {
		if discovery == nil ||
			discovery.SourceID != state.Config.SourceID {
			return fmt.Errorf(
				"FI receipt discovery source identity mismatch: %w",
				err,
			)
		}

		if state.Quarantined {
			return nil
		}

		if err := m1PersistSourceQuarantine(
			state,
			"RECORDED_RECEIPT_INVALID",
			"",
			fmt.Sprint(discovery.Cause),
		); err != nil {
			return err
		}

		state.Quarantined = true
		state.Repair.Reset()

		fmt.Fprintf(
			os.Stderr,
			"SOURCE QUARANTINED source=%s reason=RECORDED_RECEIPT_INVALID action=operator_review_required detail=%q\n",
			discovery.SourceID,
			discovery.Cause,
		)
		return nil
	}

	var conflict *sourceReconcileConflictError
	if !errors.As(err, &conflict) {
		return err
	}

	if conflict == nil ||
		conflict.SourceID != state.Config.SourceID {
		return fmt.Errorf(
			"FI ingest reconciliation conflict identity mismatch: %w",
			err,
		)
	}

	if state.Quarantined {
		return nil
	}

	if err := m1PersistSourceQuarantine(
		state,
		"RELATIONAL_CONFLICT",
		conflict.GenerationID,
		conflict.Detail,
	); err != nil {
		return err
	}

	state.Quarantined = true
	state.Repair.Reset()

	fmt.Fprintf(
		os.Stderr,
		"SOURCE QUARANTINED source=%s generation=%s reason=RELATIONAL_CONFLICT action=operator_review_required detail=%q\n",
		conflict.SourceID,
		conflict.GenerationID,
		conflict.Detail,
	)

	return nil
}

// runScheduledSourcePass leaves quarantined sources inactive while
// continuing to schedule other enabled sources.
func runScheduledSourcePass(
	state *sourceSessionState,
	run func(*sourceSessionState) error,
) error {
	if state == nil {
		return errors.New("FI ingest source state is required")
	}
	if run == nil {
		return errors.New("FI ingest source runner is required")
	}
	if state.Quarantined {
		return nil
	}

	return quarantineSourceConflict(state, run(state))
}

// runStartupSourcePlan handles a source-specific startup reconciliation
// conflict without preventing other enrolled sources from starting.
// Unclassified failures remain fatal.
func runStartupSourcePlan(
	state *sourceSessionState,
	plan recordingest.ReconcilePlan,
	ingest func() error,
) error {
	if state == nil {
		return errors.New("FI startup source state is required")
	}
	if ingest == nil {
		return errors.New("FI startup ingest operation is required")
	}
	if state.Quarantined {
		return nil
	}

	if err := quarantineSourceConflict(
		state,
		reconcileConflictError(plan),
	); err != nil {
		return err
	}

	if state.Quarantined {
		return nil
	}

	return quarantineSourceConflict(state, ingest())
}
