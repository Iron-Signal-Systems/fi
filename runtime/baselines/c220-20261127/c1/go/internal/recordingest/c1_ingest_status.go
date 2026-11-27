//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// An immutable original receipt READY marker may remain after a process
// crash occurring AFTER atomic canonical Accepted but BEFORE marker cleanup.
// Query fi-sor over a DISTINCT authenticated TLS 1.3 one-frame Status
// session before any new C1 SQL work. fi-ingest never opens PostgreSQL.
package recordingest

import (
    "context"
    "crypto/tls"
    "errors"
    "fmt"
    "net"
    "time"

    "github.com/Iron-Signal-Systems/fi/go/internal/c1handoff"
)

// ProbeC1CanonicalAccepted may ONLY return true from a matching read-only
// fi-sor canonical journal response bound to original signed custody.
// A transport failure NEVER means not accepted: the caller must stop.
func ProbeC1CanonicalAccepted(ctx context.Context,c C1IngestTransport,
    source,generation,receiptSHA string)(bool,error){
    if ctx==nil||source==""||generation==""||c.SoRAddress==""{
        return false,errors.New("C1 status: signed source, generation and SoR peer required")
    }
    frame:=c1handoff.Frame{Kind:c1handoff.Status,Sequence:1,
        SourceID:source,GenerationID:generation,ReceiptSHA256:receiptSHA}
    if err:=frame.Validate();err!=nil{return false,err}
    identity,err:=c1handoff.ClientTLSConfig(c.TLSIdentity,c.ExpectedSoRServerDNS)
    if err!=nil{return false,err}
    identity.MinVersion=tls.VersionTLS13
    netDialer:=&net.Dialer{Timeout:15*time.Second}
    conn,err:=tls.DialWithDialer(netDialer,"tcp4",c.SoRAddress,identity)
    if err!=nil{return false,fmt.Errorf("C1 status: fi-sor authenticated connection: %w",err)}
    client,err:=c1handoff.NewClient(conn)
    if err!=nil{conn.Close();return false,err}
    defer client.Close()
    return client.QueryStatus(ctx,frame)
}
