// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Private W128/K32/P3/F3 experiment only. The normal H16 and production
// ingestion paths retain their existing flush-on-family-transition behavior.
package recordingest

import (
    "context"
    "errors"
)

type privateMixedFamilyBuffersKey struct{}

// WithPrivateMixedFamilyBuffers enables independent bounded Security and
// File/USN buffers ONLY in the explicitly isolated signed-cache benchmark.
// The W128 SQL window and K32 processing boundary remain unchanged.
// Neither the receiver trust model nor ordinary ingestion can select this.
func WithPrivateMixedFamilyBuffers(ctx context.Context) (context.Context, error) {
    if ctx == nil || !usePrivateSinglePassSecurity(ctx) ||
        joinedBacklogChunkRecords(ctx) != 32768 ||
        fileBulkLimitsFromContext(ctx).Name != "F3" {
        return nil, errors.New("FI private mixed buffers require isolated W128/K32/P3/F3 Security field context")
    }
    return context.WithValue(ctx, privateMixedFamilyBuffersKey{}, true), nil
}

// Mode selection must never silently fall back to ordinary flushing.
// The H16 setter validates the fixed profile; ingestSourceBatch validates
// the presence of an active K32 buffer state once per signed batch.
func privateMixedFamilyBuffersEnabled(ctx context.Context) bool {
    return ctx != nil && ctx.Value(privateMixedFamilyBuffersKey{}) == true
}

// Called before reading signed source rows. A broken K32 wiring is a hard
// failure, not a hidden benchmark of the old transition-flush behavior.
func validatePrivateFamilyRoute(ctx context.Context) error {
    if ctx == nil || ctx.Value(privateMixedFamilyBuffersKey{}) != true {
        return nil
    }
    if !usePrivateSinglePassSecurity(ctx) ||
        joinedBacklogChunkRecords(ctx) != 32768 ||
        fileBulkLimitsFromContext(ctx).Name != "F3" {
        return errors.New("FI PRIVATE BUFFER ROUTE STOP: private H16 profile context changed")
    }
    chunk, ok := ctx.Value(backlogTypedChunkContextKey{}).(backlogTypedChunkDirective)
    if !ok || chunk.state == nil || chunk.state.fileBulk == nil {
        return errors.New("FI PRIVATE BUFFER ROUTE STOP: signed batch has no active K32 typed buffer")
    }
    return nil
}

// This decision is exercised by ingestSourceBatch itself. A transition
// between Security and File/USN never flushes either partially filled buffer
// in the private candidate. The existing bounded size/byte checks and K32
// finish still flush them. In the first mixed-family experiment, other kinds
// remain ordering barriers. The separate private dependency experiment permits
// independent Security coverage and ordered USN queues, while unaudited kinds
// remain conservative ordering fences. The ordinary paths are unchanged.
type securityFileFlushDecision struct {
    security bool
    files    bool
}

func securityFileFlushBeforeKind(ctx context.Context, kind string) securityFileFlushDecision {
    // Coverage already has its own bounded projection buffer. The dedicated
    // USN dependency queue retains source-custody order, so neither family
    // needs to force unrelated Security/File COPY when explicitly enabled.
    if privateDependencyBuffersEnabled(ctx) &&
        (kind == "WindowsSecurityCoverage" || privateUSNDependentKind(kind)) {
        return securityFileFlushDecision{}
    }
    mixed := privateMixedFamilyBuffersEnabled(ctx)
    switch kind {
    case "WindowsSecurityEvent":
        return securityFileFlushDecision{files: !mixed}
    case "FileObservation", "USNObjectObservation":
        return securityFileFlushDecision{security: !mixed}
    default:
        return securityFileFlushDecision{security: true, files: true}
    }
}

// A mixed buffer can contain sparse source ordinals even when all records
// belong to one signed batch. The BETWEEN-based ID lookup is ONLY safe when
// ordinals truly form a contiguous range. Otherwise use exact key matching.
func bulkSourceIDsAreContiguousSingleBatch(batchIDs, ordinals []int64) bool {
    if len(batchIDs) == 0 || len(batchIDs) != len(ordinals) {
        return false
    }
    for i := 1; i < len(batchIDs); i++ {
        if batchIDs[i] != batchIDs[0] || ordinals[i] != ordinals[i-1]+1 {
            return false
        }
    }
    return true
}

// The original File/USN source COPY demanded consecutive ordinal numbers.
// Independent family buffers legitimately skip over interleaved Security
// records. For the private candidate, only STRICTLY increasing ordinals are
// required; original identity uniqueness remains enforced in PostgreSQL.
func fileOrdinalInvalidForBatch(ctx context.Context, current, previous int64) bool {
    if current <= previous {
        return true
    }
    return !privateMixedFamilyBuffersEnabled(ctx) && current != previous+1
}
