// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// P7 private W512 staging session. This makes the three phase protocol
// explicit: (1) committed source + field-partition setup;
// (2) 5 concurrent typed SQL writers; (3) one verified atomic typed marker.
// It does NOT allow the old StageBacklogTypedWindow single transaction to
// silently masquerade as 5 independent SQL connections.
package recordingest

import (
    "context"
    "errors"
    "fmt"

    "github.com/jackc/pgx/v5"
)

type privateP7WindowSession struct{
    ctx context.Context
    control *pgx.Conn
    staged privateP7PreparedWindow
    sink *privateP7FiveWriter
    buffers *privateP6Buffers
    generation *PreparedGeneration
    descriptor BacklogCheckpointDescriptor
    final bool
    closed bool
    published bool
}

// Requires StageBacklogSourceWindow / authenticated artifacts to have
// committed BEFORE this starts. The caller must supply FI's real
// ntfsStageTimingCounters and usnCaptureState via ctx, not fabricated ones.
func newPrivateP7WindowSession(ctx context.Context,control *pgx.Conn,
    dsn,expectedDataDir string,g *PreparedGeneration,
    descriptor BacklogCheckpointDescriptor,index int,final bool,
)(*privateP7WindowSession,error){
    if ctx==nil||control==nil||g==nil||!privateP7FiveWriterSelected(){
        return nil,errors.New("FI P7: invalid private staged W512 session configuration")
    }
    if _,ok:=ctx.Value(ntfsStageTimingContextKey{}).(*ntfsStageTimingCounters);!ok{
        return nil,errors.New("FI P7: original File source/reuse validation ledger absent")
    }
    if ctx.Value(usnCaptureContextKey{})==nil{
        return nil,errors.New("FI P7: original USN capture state absent")
    }
    // NOTE: exact control PG clone identity/durability is independently
    // verified by the parent caller; five family + one source connection
    // revalidate their own PostgreSQL data_directory before any writes.
    setup,err:=privateP7PrepareCommittedWindow(ctx,control,descriptor,index)
    if err!=nil{return nil,err}
    writer,err:=newPrivateP7PostgresFiveWriter(ctx,dsn,descriptor.SourceID,
        setup.FieldPartition,expectedDataDir)
    if err!=nil{return nil,err}
    buffers,err:=newPrivateP6Buffers(index,writer)
    if err!=nil{
        _=writer.Close(context.Background())
        return nil,err
    }
    fmt.Printf("FI P7 WINDOW START index=%d typed_sql_writers=5 parent_ledger_connections=1 family_buffers=5 bounded_bytes=%d setup=committed typed_marker=pending\n",
        index,privateP7MaxQueuedBytes)
    return &privateP7WindowSession{ctx:ctx,control:control,staged:setup,
        sink:writer,buffers:buffers,generation:g,descriptor:descriptor,final:final},nil
}
func(s *privateP7WindowSession) Add(ctx context.Context,r privateP6Record)error{
    if s==nil||s.closed||s.published||s.buffers==nil{
        return errors.New("FI P7: signed window already closed or published")
    }
    return s.buffers.Add(ctx,r)
}
func(s *privateP7WindowSession) Publish(ctx context.Context)(privateP7PublishedWindow,error){
    var empty privateP7PublishedWindow
    if s==nil||s.closed||s.published||s.buffers==nil{
        return empty,errors.New("FI P7: window not active or already published")
    }
    // The original private P6 buffer Finish verifies every source parent
    // and family count. In P7 it additionally waits for all five SQL ACKs.
    if err:=s.buffers.Finish(ctx);err!=nil{return empty,err}
    done,err:=privateP7PublishVerifiedWindow(ctx,s.control,s.sink,
        s.generation,s.descriptor,s.staged.Index,
        s.staged.FieldPartition,s.final)
    if err!=nil{return empty,err}
    s.published=true
    return done,nil
}
func(s *privateP7WindowSession) Close(ctx context.Context)error{
    if s==nil{return nil}
    if s.closed{return errors.New("FI P7: window session already closed")}
    s.closed=true
    if s.sink==nil{return nil}
    err:=s.sink.Close(ctx)
    if !s.published{
        // Do not issue compensating DELETEs into partially committed
        // private staging rows. The entire disposable PostgreSQL clone
        // MUST be discarded and rebuilt from authenticated source seed.
        fmt.Printf("FI P7 WINDOW REJECTED index=%d typed_marker=absent clone_disposal=required\n",
            s.staged.Index)
    }
    return err
}
