// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
    "context"
    "errors"

    "github.com/jackc/pgx/v5"
)

// ErrC1SORNotIntegrated keeps this unreleased development service disabled
// until the original C1 source reader/buffers, SoR-local shared SQL workers,
// durable cross-jail acknowledgements, asynchronous independent verification,
// and populated-SoR final transaction are wired and acceptance-tested.
var ErrC1SORNotIntegrated = errors.New("FI C1: SoR-side C1 processing and cross-jail commit protocol not yet integrated; old ingester forbidden")

// C1ServiceAdmission is checked before the ingest daemon opens its SQL
// connection or starts a durable journal attempt. No operator env var may
// bypass this gate: the implementation must replace it with a proven runtime.
func C1ServiceAdmission() error {
    return ErrC1SORNotIntegrated
}

// IngestC1PreparedGeneration is the intended service dispatch target.
// There is deliberately NO fallback to IngestPreparedGeneration. Both
// ingest and SoR processing must be replaced with the accepted C1 model.
func IngestC1PreparedGeneration(_ context.Context, _ *pgx.Conn, _ string, _ *PreparedGeneration) (IngestResult,error) {
    return IngestResult{}, ErrC1SORNotIntegrated
}
