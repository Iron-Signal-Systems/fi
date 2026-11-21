// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// C1's SQL worker connections originate from fi-ingest but PostgreSQL
// executes their SQL in fi-sor. This guard pins the remote workload
// address and prevents an accidental local-clone or wrong-DB connection.
package recordingest

import (
    "errors"
    "fmt"
    "net/netip"
    "strings"
)

// C1SoRBackendIdentity is evidence reported by the PostgreSQL backend,
// not an identity asserted by the FI ingest worker.
type C1SoRBackendIdentity struct {
    Database string
    Role string
    ServerAddress string
    ClientAddress string
    InRecovery bool
    BackendPID int32
}

// ValidateC1SoRBackendIdentity is the fail-closed connection preflight for
// every C1 ordered-parent, shared-family, or independent verifier connection.
// The expected address must come from the separately approved fi-sor workload
// configuration, never be learned from the connection being validated.
func ValidateC1SoRBackendIdentity(expectedServerIP string, got C1SoRBackendIdentity) error {
    expected, err := netip.ParseAddr(strings.TrimSpace(expectedServerIP))
    if err != nil || !expected.IsValid() || expected.IsUnspecified() ||
        expected.IsLoopback() || expected.IsMulticast() {
        return errors.New("FI C1 SoR: an explicit nonlocal workload IP is required")
    }
    if got.Database != "fi" {
        return fmt.Errorf("FI C1 SoR: database %q is not authoritative fi", got.Database)
    }
    if got.Role != "fi_ingest" {
        return fmt.Errorf("FI C1 SoR: role %q is not fi_ingest", got.Role)
    }
    if got.InRecovery || got.BackendPID <= 0 {
        return errors.New("FI C1 SoR: backend must be a writable primary with a valid PostgreSQL PID")
    }
    server, err := netip.ParseAddr(strings.TrimSpace(got.ServerAddress))
    if err != nil || !server.IsValid() || server != expected {
        return fmt.Errorf("FI C1 SoR: backend server address %q differs from pinned workload IP", got.ServerAddress)
    }
    client, err := netip.ParseAddr(strings.TrimSpace(got.ClientAddress))
    if err != nil || !client.IsValid() || client.IsUnspecified() {
        return errors.New("FI C1 SoR: a remote TCP client address is required; local sockets are forbidden")
    }
    return nil
}
