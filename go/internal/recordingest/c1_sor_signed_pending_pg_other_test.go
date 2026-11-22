//go:build !freebsd && fi_c1_sor_dev && fi_c1_schema_pg_integration

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Original signed receiver fixture uses native FreeBSD transport custody.
// Linux disposable PostgreSQL validates the remaining same SQL transactions.
package recordingest

import (
    "context"
    "testing"

    "github.com/jackc/pgx/v5"
)

func c1TestSignedOriginalPendingPostgres18(_ *testing.T,_ context.Context,
    _,_ *pgx.Conn) {}

func c1TestSignedMTLSRAMPostgres18(_ *testing.T,_ context.Context,
    _,_,_ *pgx.Conn) {}
