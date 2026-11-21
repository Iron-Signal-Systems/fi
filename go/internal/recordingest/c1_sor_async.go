//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// C1's real SoR SQL worker pool retains its original asynchronous
// Parent/Family/USN work scheduling. A network ACK waits on the specific
// PostgreSQL COMMIT broadcast fence, never on a queue/admission receipt.
package recordingest

import (
    "context"
    "errors"
    "fmt"

    "github.com/Iron-Signal-Systems/fi/go/internal/c1handoff"
)

func c1SourceCommitted(ctx context.Context,ack *privateC1SourceAck)<-chan error{
    result:=make(chan error,1)
    go func(){
        defer close(result)
        if ack==nil||ack.done==nil{
            result<-errors.New("FI C1 SoR: missing PostgreSQL commit fence")
            return
        }
        select{
        case <-ack.done:
            result<-ack.err
        case <-ctx.Done():
            result<-fmt.Errorf("FI C1 SoR: SQL commit outcome uncertain after cancellation: %w",ctx.Err())
        }
    }()
    return result
}

// Enqueue is invoked on exactly ONE authenticated fi-sor dispatcher
// goroutine. Every call checks original source batch/ordinal/digest and
// family identity before submitting to the native C1 shared SQL pool.
// Admission is NOT COMMIT, so the returned read-only future is mandatory.
func (s *c1SoRCommitHandler) Enqueue(ctx context.Context,
    f c1handoff.Frame)(<-chan error,error){
    if ctx==nil||s==nil||s.sink==nil||s.drained {
        return nil,errors.New("FI C1 SoR: invalid active asynchronous SQL session")
    }
    pool,ok:=s.sink.(*privateC1FiveSQL)
    if !ok || pool==nil {
        return nil,errors.New("FI C1 SoR: original native C1 shared SQL pool required")
    }
    rows,err:=s.prepareRows(f)
    if err!=nil{return nil,err}
    if f.Kind==c1handoff.Source{
        if err:=pool.Source(ctx,rows);err!=nil{return nil,err}
        ack:=pool.sourceLast
        if ack==nil{return nil,errors.New("FI C1 SoR: SourceParent accepted without durable fence")}
        // This count is ADMISSION only. privateC1CommitReady and the
        // original SQL CommitSource enforce durable group completion.
        s.accountSource(rows)
        return c1SourceCommitted(ctx,ack),nil
    }
    family:=privateP6Family(f.Kind-2)
    if err:=pool.Family(ctx,family,rows);err!=nil{return nil,err}
    ack:=pool.lanes[family].latestCommitted
    if ack==nil{return nil,errors.New("FI C1 SoR: typed family accepted without durable fence")}
    s.typedRows+=int64(len(rows))
    return c1SourceCommitted(ctx,ack),nil
}
