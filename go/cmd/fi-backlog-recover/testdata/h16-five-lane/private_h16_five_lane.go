// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Development-only fifth independently drained family lane. This source is
// copied ONLY into the disposable, historically pinned H16 W128 replay build.
// Never install it in the canonical ingest path.
package recordingest

import (
    "context"
    "errors"
)

type privateH16FiveLaneKey struct{}
type privateH16FiveLaneTelemetryKey struct{}

// The five independently bounded logical worker lanes are Security event,
// File source, File projection, Security coverage, and ordered USN dependency.
// The joined signed-source ledger is a separate pre-existing custody buffer,
// not an additional SQL transaction or a second copy of these five payloads.
// No new record buffer is allocated: the coordinator uses the original
// backlogTypedChunkState slices and fileObservationBulkState by reference.
type privateH16FiveLaneTelemetry struct {
    FileSourceDrains uint64
    DeferredFileProjection uint64
    DependencyProjectionDrains uint64
    OrderingProjectionDrains uint64
    FinalProjectionDrains uint64
}

// WithPrivateH16FiveLaneCoordinator is opt-in AFTER mixed/dependency families
// and BEFORE the original H16 hash-only F3H16 profile is selected.
// The caller must also satisfy all CLI-specific W128/signed-cache restrictions.
// It cannot change historical H16, SoR, receiver, or another recovery mode.
func WithPrivateH16FiveLaneCoordinator(ctx context.Context) (context.Context,error) {
    if ctx == nil || !privateDependencyBuffersEnabled(ctx) ||
       !usePrivateSinglePassSecurity(ctx) ||
       joinedBacklogChunkRecords(ctx) != 32768 ||
       !privateH16CombinedFileProfileValid(ctx) ||
       fileBulkLimitsFromContext(ctx).Name != "F3" {
       return nil,errors.New("FI private five-lane coordinator requires exact isolated W128/K32/P3/F3 dependency context")
    }
    return context.WithValue(ctx,privateH16FiveLaneKey{},true),nil
}

func privateH16FiveLaneEnabled(ctx context.Context) bool {
    return ctx != nil && ctx.Value(privateH16FiveLaneKey{}) == true &&
       privateDependencyBuffersEnabled(ctx) &&
       usePrivateSinglePassSecurity(ctx) &&
       joinedBacklogChunkRecords(ctx) == 32768 &&
       privateH16CombinedFileProfileValid(ctx)
}

func privateH16FiveLaneStats(ctx context.Context) *privateH16FiveLaneTelemetry {
    if ctx == nil {return nil}
    s,_:=ctx.Value(privateH16FiveLaneTelemetryKey{}).(*privateH16FiveLaneTelemetry)
    return s
}

// Only unaudited record families are conservative source-order fences.
// USN records are in the separate ordered dependency lane and require File
// parent projection to be flushed BEFORE dependency projection. A transition
// between Security and File/coverage does not flush either queue.
func privateH16FiveLaneOrderingFence(kind string) bool {
    switch kind {
    case "WindowsSecurityEvent","FileObservation","WindowsSecurityCoverage",
         "USNReadBoundary","USNObjectObservation":
        return false
    default:
        return true
    }
}

// The existing fileObservationBulkState.add() enforces its own F3 row/byte
// limits. Source COPY completion is NOT a reason to flush that projection
// queue. Explicit drains are required on dependency/order barriers and at
// final W128 before the original typed marker/commit.
func privateH16FiveLaneDeferProjectionAfterSource(ctx context.Context) bool {
    return privateH16FiveLaneEnabled(ctx)
}
