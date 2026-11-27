// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package backendinstall

import (
    "strings"
    "testing"
)

func TestManagedIngestAdaptiveSQLWorkersBound(t *testing.T) {
    requiredRunner := []string{
        `fi_ingest_worker_sql_workers_max="${fi_ingest_worker_sql_workers_max:-5}"`,
        `[1-9]|[12][0-9]|3[0-2])`,
        `-sql-workers-max "$fi_ingest_worker_sql_workers_max"`,
    }
    for _, value := range requiredRunner {
        if !strings.Contains(runtimeAssetIngestRunner, value) {
            t.Fatalf("managed runner missing adaptive SQL worker limit contract %q", value)
        }
    }
    if !strings.Contains(runtimeAssetIngestRCConfig,
        `fi_ingest_worker_sql_workers_max="5"`) {
        t.Fatal("managed FI backend config missing SQL pool maximum (default 5)")
    }
    if !strings.Contains(runtimeAssetIngestRunner,
        `-workers "$fi_ingest_worker_workers"`) {
        t.Fatal("source generation worker count must remain independently configured")
    }
}
