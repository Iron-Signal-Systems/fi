// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// RecoverBacklogGenerationToPrivateShadow runs the existing bounded recovery
// operations in signed source-batch order. Each window commits only to the
// private recovery schemas, with its own atomic source and typed checkpoints.
// Repeating this call after a crash verifies and reuses completed checkpoints,
// then resumes at the first unfinished operation.
//
// The caller must supply an independently authenticated PreparedGeneration
// from the existing trust-checked generation loader. This is an opt-in private
// recovery operation, not an Accepted ingest, SoR write or query publication.
// The private recovery schemas are currently installed ONLY by isolated tests.
func RecoverBacklogGenerationToPrivateShadow(
	ctx context.Context,
	reader, writer *pgx.Conn,
	generation *PreparedGeneration,
	limits BacklogWindowLimits,
	privateRoot string,
) (BacklogGenerationVerification, error) {
	var empty BacklogGenerationVerification
	if ctx == nil || reader == nil || writer == nil || reader == writer {
		return empty, errors.New("FI backlog recovery: distinct reader and writer connections required")
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	descriptors, err := DescribeBacklogWindows(generation, limits)
	if err != nil {
		return empty, fmt.Errorf("FI backlog recovery: invalid signed window plan: %w", err)
	}
	// The destination must be an existing, real, private 0700 directory.
	// Never create a permissive default directory or follow a symlink.
	if err := verifyPrivateBacklogRoot(privateRoot); err != nil {
		return empty, fmt.Errorf("FI backlog recovery: private root: %w", err)
	}
	for i := range descriptors {
		if err := ctx.Err(); err != nil {
			return empty, err
		}
		if _, err := MaterializeBacklogWindow(ctx, generation, limits, i, privateRoot); err != nil {
			return empty, fmt.Errorf("FI backlog recovery: window %d artifact: %w", i, err)
		}
		if err := RecordVerifiedBacklogArtifactWindow(ctx, writer, generation, limits, i, privateRoot); err != nil {
			return empty, fmt.Errorf("FI backlog recovery: window %d artifact ledger: %w", i, err)
		}
		if err := StageVerifiedBacklogSourceWindow(ctx, writer, generation, limits, i, privateRoot); err != nil {
			return empty, fmt.Errorf("FI backlog recovery: window %d source: %w", i, err)
		}
		if err := StageBacklogTypedWindow(ctx, reader, writer, generation, limits, i, privateRoot); err != nil {
			return empty, fmt.Errorf("FI backlog recovery: window %d typed: %w", i, err)
		}
	}
	// Only the original signed generation may pass this read-only check.
	// No partial window or intermediate marker is ever called accepted.
	result, err := VerifyCompleteBacklogTypedGeneration(ctx, reader, generation, limits)
	if err != nil {
		return empty, fmt.Errorf("FI backlog recovery: whole-generation verification: %w", err)
	}
	return result, nil
}
