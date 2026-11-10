// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Experimental file COPY limits. The production worker never reads environment
// variables to select a profile; only explicitly enabled integration tests set
// a context value. A missing context value retains the accepted F1 limits.
package recordingest

import (
	"context"
	"fmt"
)

type fileBulkProfileContextKey struct{}

type fileBulkLimits struct {
	Name              string
	SourceMaxRecords  int
	SourceMaxBytes    int64
	ObserveMaxRecords int
	ObserveMaxBytes   int64
	HashMaxRows       int
	HashMaxBytes      int
	ChildMaxRows      int
}

func defaultFileBulkLimits() fileBulkLimits {
	return fileBulkLimits{
		Name:              "F1",
		SourceMaxRecords:  fileSourceBulkMaxRecords,
		SourceMaxBytes:    fileSourceBulkMaxBytes,
		ObserveMaxRecords: fileObservationBulkMaxRecords,
		ObserveMaxBytes:   fileObservationBulkMaxBytes,
		HashMaxRows:       contentHashCopyMaxRows,
		HashMaxBytes:      contentHashCopyMaxBytes,
		ChildMaxRows:      fileChildCopyMaxRows,
	}
}

// withFixedFileBulkProfile is only called by the explicitly opt-in isolated
// signed-generation replay test. It does not modify package globals or allow
// a runtime worker setting to weaken accepted production bounds.
func withFixedFileBulkProfile(ctx context.Context, name string) (context.Context, error) {
	if ctx == nil {
		return nil, fmt.Errorf("FI file bulk profile requires context")
	}
	limits := defaultFileBulkLimits()
	switch name {
	case "F1":
	case "F2":
		limits = fileBulkLimits{"F2", 4096, 16 << 20, 4096, 16 << 20, 4096, 4 << 20, 2048}
	case "F3":
		limits = fileBulkLimits{"F3", 8192, 32 << 20, 8192, 32 << 20, 8192, 8 << 20, 4096}
	case "F4":
		limits = fileBulkLimits{"F4", 16384, 64 << 20, 16384, 64 << 20, 16384, 16 << 20, 4096}
	default:
		return nil, fmt.Errorf("FI unknown file bulk profile %q", name)
	}
	return context.WithValue(ctx, fileBulkProfileContextKey{}, limits), nil
}

func fileBulkLimitsFromContext(ctx context.Context) fileBulkLimits {
	if ctx != nil {
		if selected, ok := ctx.Value(fileBulkProfileContextKey{}).(fileBulkLimits); ok {
			return selected
		}
	}
	return defaultFileBulkLimits()
}

// WithPrivateFileHashH16 selects one isolated COPY-batching experiment without
// changing any other F3 setting or the production F1 defaults. The signed W128
// recovery CLI permits this only for its guarded deferred/private clone path.
//
// The original 8,192-row/8-MiB hash writer cost increased in later W128
// windows. Doubling only its bounds tests whether fewer synchronous
// PostgreSQL COPY calls improve wall time; it does NOT bypass FK, hash shape,
// row validation, transaction boundaries, or per-row digest verification.
//
// Requiring the exact original F3 profile prevents accidentally composing
// experimental contexts or silently weakening bounds in other ingest paths.
func WithPrivateFileHashH16(ctx context.Context) (context.Context, error) {
	if ctx == nil {
		return nil, fmt.Errorf("FI private hash H16: context required")
	}
	original := fileBulkLimitsFromContext(ctx)
	if original != (fileBulkLimits{
		Name: "F3", SourceMaxRecords: 8192, SourceMaxBytes: 32 << 20,
		ObserveMaxRecords: 8192, ObserveMaxBytes: 32 << 20,
		HashMaxRows: 8192, HashMaxBytes: 8 << 20, ChildMaxRows: 4096,
	}) {
		return nil, fmt.Errorf("FI private hash H16: requires unmodified F3 profile")
	}
	adjusted := original
	adjusted.Name = "F3H16"
	adjusted.HashMaxRows = 16384
	adjusted.HashMaxBytes = 16 << 20
	return context.WithValue(ctx, fileBulkProfileContextKey{}, adjusted), nil
}
