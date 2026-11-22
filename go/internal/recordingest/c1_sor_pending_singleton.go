//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Fail-closed, PostgreSQL session-owned singleton for C1 pending generation
// processing. The session holds no data transactions and no writable custody.
package recordingest

import (
    "context"
    "errors"
    "fmt"
)

const c1PendingSessionLockKey int64=0x4631433153455353

func (s *C1SoRService)acquirePendingSessionLock(ctx context.Context)error{
    if s==nil||ctx==nil{return errors.New("C1 pending: missing SoR singleton context")}
    if s.pendingSession!=nil{return errors.New("C1 pending: singleton already acquired")}
    conn,_,err:=openC1SoRLocalSQL(ctx,s.DSN,"")
    if err!=nil{return err}
    var acquired bool
    err=conn.QueryRow(ctx,"SELECT pg_try_advisory_lock($1::bigint)",
        c1PendingSessionLockKey).Scan(&acquired)
    if err!=nil||!acquired{
        _=conn.Close(context.Background())
        if err!=nil{return err}
        return errors.New("C1 pending: another fi-sor process owns the active generation")
    }
    // A PostgreSQL disconnect destroys the ownership lock: every subsequent
    // SQL handoff then fails rather than silently acknowledging a new owner.
    s.pendingSession=conn
    return nil
}

func (s *C1SoRService)pendingLockHealthy(ctx context.Context)error{
    if s==nil||s.pendingSession==nil||ctx==nil{
        return errors.New("C1 pending: SQL generation ownership absent")
    }
    var n int64
    err:=s.pendingSession.QueryRow(ctx,`SELECT count(*) FROM pg_locks
      WHERE pid=pg_backend_pid() AND locktype='advisory' AND granted
      AND objsubid=1 AND classid=$1::oid AND objid=$2::oid`,
      int64(uint64(c1PendingSessionLockKey)>>32),
      int64(uint64(c1PendingSessionLockKey)&0xffffffff)).Scan(&n)
    if err!=nil||n<=0{
        return fmt.Errorf("C1 pending: SQL session ownership lost or unverifiable: %v",err)
    }
    return nil
}

// The owner connection is a long-lived fi-sor-local SQL session. The
// normal SQL worker and dedicated publisher use separate connections.
