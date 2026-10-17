// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package main

import (
	"context"
	"errors"
	"fmt"
)

// m1RestoreSourceQuarantineStates runs before the worker makes its
// first PostgreSQL connection. Every enabled source is bound to the
// validated persistent store, including sources not quarantined.
//
// It must fail the entire worker when state cannot be verified.
func m1RestoreSourceQuarantineStates(
	states []sourceSessionState,
	store m1QuarantineStore,
) error {
	if len(states) == 0 {
		return errors.New(
			"FI quarantine restoration requires enabled sources",
		)
	}

	sourceIDs := make([]string, 0, len(states))

	for index := range states {
		state := &states[index]

		if !state.Config.SourceNamespaces {
			return fmt.Errorf(
				"FI source %q is not configured for namespaces",
				state.Config.SourceID,
			)
		}

		if state.Config.QuarantineRoot != store.Root {
			return fmt.Errorf(
				"FI source %q quarantine root differs from worker root",
				state.Config.SourceID,
			)
		}

		if state.Quarantined ||
			state.QuarantineStore != nil {
			return fmt.Errorf(
				"FI source %q quarantine state already initialized",
				state.Config.SourceID,
			)
		}

		sourceIDs = append(sourceIDs, state.Config.SourceID)
	}

	// The entire store must validate before any source is activated.
	markers, err := store.Load(sourceIDs)
	if err != nil {
		return fmt.Errorf(
			"validate FI durable quarantine inventory: %w",
			err,
		)
	}

	for index := range states {
		state := &states[index]
		state.QuarantineStore = &store

		marker, found := markers[state.Config.SourceID]
		if !found {
			continue
		}

		state.Quarantined = true
		state.Repair.Reset()

		fmt.Printf(
			"SOURCE QUARANTINE RESTORED source=%s reason=%s generation=%s created=%s action=operator_review_required\n",
			marker.SourceID,
			marker.Reason,
			marker.GenerationID,
			marker.CreatedAtUTC,
		)
	}

	return nil
}

// m1PersistSourceQuarantine establishes durable source isolation
// before the in-memory state is allowed to transition.
//
// Legacy flat-layout operation preserves its previous behavior.
func m1PersistSourceQuarantine(
	state *sourceSessionState,
	reason string,
	generationID string,
	detail string,
) error {
	if state == nil {
		return errors.New(
			"FI quarantine persistence requires source state",
		)
	}

	if !state.Config.SourceNamespaces {
		return nil
	}

	if state.KeeperClient != nil {
		if state.QuarantineStore != nil || state.Config.QuarantineRoot == "" {
			return errors.New("FI worker quarantine authority is ambiguous or incomplete")
		}
		if err := state.KeeperClient.Publish(
			context.Background(), state.Config.SourceID,
			reason, generationID, detail,
		); err != nil {
			return fmt.Errorf("keeper quarantine publication failed closed for %q: %w",
				state.Config.SourceID, err)
		}
		return nil
	}

	// This worker-owned store exists only for the pre-keeper tests.
	// The operational runWorker path above never initializes it.
	if state.QuarantineStore == nil ||
		state.Config.QuarantineRoot == "" ||
		state.QuarantineStore.Root != state.Config.QuarantineRoot {
		return fmt.Errorf(
			"FI source %q has no valid durable quarantine store",
			state.Config.SourceID,
		)
	}

	if err := state.QuarantineStore.Persist(
		state.Config.SourceID,
		reason,
		generationID,
		detail,
	); err != nil {
		return fmt.Errorf(
			"persist FI source %q quarantine before isolation: %w",
			state.Config.SourceID,
			err,
		)
	}

	return nil
}
