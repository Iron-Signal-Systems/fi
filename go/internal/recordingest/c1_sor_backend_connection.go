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

// OpenC1SoRSQLConnection opens one SQL worker connection from fi-ingest to
// the PostgreSQL primary running inside fi-sor, then checks server-reported
// endpoint, database, service role and backend PID before any data writes.
// PostgreSQL itself executes all SQL work in the fi-sor jail. There is no
// alternate Go SQL writer service in fi-ingest or fi-receiver.
func OpenC1SoRSQLConnection(ctx context.Context, dsn, expectedServerIP string) (*pgx.Conn, C1SoRBackendIdentity, error) {
    if ctx == nil || dsn == "" || expectedServerIP == "" {
        return nil, C1SoRBackendIdentity{}, errors.New("FI C1 SoR: context, DSN and pinned workload IP required")
    }
    conn, err := pgx.Connect(ctx, dsn)
    if err != nil {
        return nil, C1SoRBackendIdentity{}, fmt.Errorf("FI C1 SoR: connect: %w", err)
    }
    var identity C1SoRBackendIdentity
    err = conn.QueryRow(ctx, `SELECT current_database(), current_user,
        COALESCE(inet_server_addr()::text, ''),
        COALESCE(inet_client_addr()::text, ''),
        pg_is_in_recovery(), pg_backend_pid()`).Scan(
        &identity.Database, &identity.Role,
        &identity.ServerAddress, &identity.ClientAddress,
        &identity.InRecovery, &identity.BackendPID,
    )
    if err == nil {
        err = ValidateC1SoRBackendIdentity(expectedServerIP, identity)
    }
    if err != nil {
        _ = conn.Close(context.Background())
        return nil, C1SoRBackendIdentity{}, fmt.Errorf("FI C1 SoR: backend validation: %w", err)
    }
    return conn, identity, nil
}

// OpenC1SoRVerifierConnection gets its own backend session, separate from
// ingestion's ordered-parent writer and SQL pool. The verifier executes
// read-only, concurrently with C1's bounded buffer and SQL workflow.
// Generation acceptance still requires every completed verification proof.
func OpenC1SoRVerifierConnection(ctx context.Context, dsn, expectedServerIP string) (*pgx.Conn, C1SoRBackendIdentity, error) {
    conn, identity, err := OpenC1SoRSQLConnection(ctx, dsn, expectedServerIP)
    if err != nil {
        return nil, C1SoRBackendIdentity{}, err
    }
    if _, err = conn.Exec(ctx, "SET default_transaction_read_only = on"); err != nil {
        _ = conn.Close(context.Background())
        return nil, C1SoRBackendIdentity{}, fmt.Errorf("FI C1 SoR: enforce verifier read-only session: %w", err)
    }
    return conn, identity, nil
}
