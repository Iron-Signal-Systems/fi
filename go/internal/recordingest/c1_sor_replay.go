//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Recovery-only C1 SQL admission. P5/P6 still send the COMPLETE original
// signed record stream; fi-sor uses read-only PostgreSQL evidence to skip
// only identical previously committed SourceParent/typed roots. There is no
// tmpfs journal, no per-batch buffer flush and no SQL writes from fi-ingest.
package recordingest

import (
    "context"
    "errors"
    "fmt"

    "github.com/Iron-Signal-Systems/fi/go/internal/c1handoff"
    "github.com/jackc/pgx/v5"
)

func c1AlreadyCommittedAck()*privateC1SourceAck{
    a:=&privateC1SourceAck{done:make(chan struct{})}
    close(a.done)
    return a
}
func c1ImmediateCommittedFuture()<-chan error{
    done:=make(chan error,1)
    done<-nil
    close(done)
    return done
}

// EnqueueReplay is NOT selected by normal clean-stage ingestion. The SoR
// startup must explicitly audit the dirty private stage and bind its own
// isolated read-only socket before enabling this path. Original signed
// (batch,ordinal,sha256) mismatches abort the entire generation.
func(s *c1SoRCommitHandler)EnqueueReplay(ctx context.Context,
    f c1handoff.Frame,read *pgx.Conn)(<-chan error,error){
    if s==nil||ctx==nil||read==nil||s.drained{
        return nil,errors.New("C1 replay: signed restart/recovery session absent")
    }
    pool,ok:=s.sink.(*privateC1FiveSQL)
    if !ok||pool==nil||pool.commitReady==nil{
        return nil,errors.New("C1 replay: native SoR SQL pool and durable group tracker required")
    }
    rows,err:=s.prepareRows(f)
    if err!=nil{return nil,err}
    tx,err:=read.BeginTx(ctx,pgx.TxOptions{IsoLevel:pgx.RepeatableRead,AccessMode:pgx.ReadOnly})
    if err!=nil{return nil,err}
    state,err:=c1AuditCommittedRowStates(ctx,tx,rows,pool.projectionSchema)
    if err!=nil{
        _=tx.Rollback(context.Background())
        return nil,fmt.Errorf("C1 replay: original signed SourceParent proof: %w",err)
    }
    if err=tx.Commit(ctx);err!=nil{return nil,err}
    selected,err:=c1PartitionRecoveredHandoff(f.Kind,rows,state)
    if err!=nil{return nil,err}
    if f.Kind==c1handoff.Source{
        // Waiting before virtual SourceParent credit prevents a later
        // typed family from outrunning any still-uncommitted prior parent.
        if len(selected.MustWrite)>0{
            if err=pool.Source(ctx,selected.MustWrite);err!=nil{return nil,err}
        }
        if len(selected.AlreadyCommitted)>0{
            if err=pool.WaitSource(ctx);err!=nil{return nil,err}
            // This is a *verified existing* PostgreSQL commit, not a
            // fabricated future for an uncommitted SQL transaction.
            pool.parentRows+=int64(len(selected.AlreadyCommitted))
            if err=pool.commitReady.CommitSource(selected.AlreadyCommitted);err!=nil{
                return nil,fmt.Errorf("C1 replay: durable existing source ready: %w",err)
            }
        }
        if len(selected.MustWrite)==0{
            pool.sourceLast=c1AlreadyCommittedAck()
        }
        if pool.sourceLast==nil{
            return nil,errors.New("C1 replay: missing ordered SourceParent commit fence")
        }
        s.accountSource(rows)
        return c1SourceCommitted(ctx,pool.sourceLast),nil
    }
    family:=privateP6Family(f.Kind-2)
    if len(selected.MustWrite)>0{
        if err=pool.Family(ctx,family,selected.MustWrite);err!=nil{return nil,err}
    }
    if len(selected.AlreadyCommitted)>0{
        lane:=pool.lanes[family]
        if lane==nil{return nil,errors.New("C1 replay: missing original shared SQL family")}
        // Virtual COMMIT credits represent only persisted rows already
        // proved byte-for-byte against original signed SourceParent input.
        lane.mu.Lock()
        lane.committed+=int64(len(selected.AlreadyCommitted))
        lane.mu.Unlock()
        if err=pool.commitReady.CommitFamily(selected.AlreadyCommitted);err!=nil{
            return nil,fmt.Errorf("C1 replay: durable existing typed ready: %w",err)
        }
    }
    s.accountTyped(rows)
    if len(selected.MustWrite)==0{
        return c1ImmediateCommittedFuture(),nil
    }
    ack:=pool.lanes[family].latestCommitted
    if ack==nil{return nil,errors.New("C1 replay: typed family accepted without SQL commit fence")}
    return c1SourceCommitted(ctx,ack),nil
}
