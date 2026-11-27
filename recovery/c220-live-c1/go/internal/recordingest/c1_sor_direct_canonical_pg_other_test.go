//go:build !freebsd && fi_c1_sor_dev && fi_c1_schema_pg_integration

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
    "context"
    "testing"

    "github.com/jackc/pgx/v5"
)

// The actual receiver-signed B process / canonical PostgreSQL acceptance
// fixture only executes on native FreeBSD. Linux integration still exercises
// the unchanged Pending and private relational tests in this suite.
func c1TestDirectCanonicalSignedPostgres18(t *testing.T,_ context.Context,
    _,_,_ *pgx.Conn) {
    t.Helper()
    t.Log("native FreeBSD-only original signed direct-canonical B/Accepted test skipped")
}
