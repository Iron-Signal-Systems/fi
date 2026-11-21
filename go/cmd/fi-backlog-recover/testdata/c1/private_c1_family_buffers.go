// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// C1 DEVELOPMENT ONLY: original P5 preparation feeds five independent P6
// family buffers and one adaptive shared PostgreSQL SQL worker pool.
// The source ledger stays ordered; the typed checkpoint is withheld until
// all family commits and relational checks complete.
package recordingest

import (
    "context"
    "errors"
    "fmt"
    "os"
    "time"
)

type privateP6WindowContextKey struct{}
func privateP6BuffersFromContext(ctx context.Context)*privateP6Buffers{
    if ctx==nil{return nil}
    b,_:=ctx.Value(privateP6WindowContextKey{}).(*privateP6Buffers)
    return b
}

type privateP6Family uint8
const(
    privateP6Security privateP6Family=iota
    privateP6File
    privateP6Coverage
    privateP6USN
    privateP6Other
    privateP6FamilyCount
)
var privateP6FamilyNames=[privateP6FamilyCount]string{
    "Security","NTFSFile","Coverage","USNDependency","Other",
}

func privateP6KindFamily(kind string)(privateP6Family,error){
    switch kind{
    case "WindowsSecurityEvent":return privateP6Security,nil
    case "FileObservation":return privateP6File,nil
    case "WindowsSecurityCoverage","WindowsSecurityContinuityGap":
        return privateP6Coverage,nil
    case "USNReadBoundary","USNObjectObservation","USNContinuityGap":
        return privateP6USN,nil
    case "CollectorIdentity","DirectoryPrincipalSnapshot","LocalPrincipalSnapshot",
        "NTFSCollectionError","SMBShareSnapshot","SupportingSourceCollectionError":
        return privateP6Other,nil
    default:return 0,fmt.Errorf("FI P6: unreviewed relational record kind %q",kind)
    }
}

// The original signed (batch index, ordinal, SHA-256, bytes) is the sole
// identity. SQL sequences must NOT substitute for signed-source order.
type privateP6Record struct{
    signedBatchIndex int
    sourceBatchID int64
    ordinal int64
    prepared SourceRecord
    selectedSinglePass bool
    singlePassSecurity securityBulkRecord
}
func (r privateP6Record) valid()bool{
    return r.signedBatchIndex>=0 && r.sourceBatchID>0 && r.ordinal>0 &&
        r.prepared.RecordBytes>0 &&
        r.prepared.RecordBytes==len(r.prepared.RawRecordBytes) &&
        r.prepared.Record.RecordKind!="" && r.prepared.Record.ScopeID!="" &&
        r.prepared.Record.Version==SpoolRecordVersion
}

// C1 schedules each family handoff on an available shared PostgreSQL worker.
// The source identity ledger uses its own ordered connection. There is NO
// single cross-connection SQL transaction; completion markers are gated.
type privateP6SQLHandoff interface{
    Source(ctx context.Context, rows []privateP6Record)error
    Family(ctx context.Context, family privateP6Family, rows []privateP6Record)error
}

type privateP6Limits struct{
    rows int
    bytes int64
}
// A per-family inactivity timer flushes pending records after 30 seconds
// without a new record for THAT family. Capacity/dependency flushes remain
// immediate, and no signed-batch/group/verifier event triggers a flush.
// The three unchanged Security candidate changes are gated to the private
// C1 two-group comparison OR the separately approved full signed replay.
// Both paths require the original P6 direct private clone. No production or
// partially selected candidate configuration is permitted.
func privateC1Security8GiBExperiment()(bool,error){
    raw:=os.Getenv("FI_C1_SECURITY_8G_EXPERIMENT")
    fullOptIn:=os.Getenv("FI_C1_SECURITY_FULL_BACKLOG_CANDIDATE")
    if raw!=""&&raw!="0"&&raw!="1"{
        return false,fmt.Errorf("FI C1: invalid Security candidate flag %q",raw)
    }
    if fullOptIn!=""&&fullOptIn!="0"&&fullOptIn!="1"{
        return false,fmt.Errorf("FI C1: invalid Security full-backlog opt-in %q",fullOptIn)
    }
    if raw!="1" {
        if fullOptIn=="1"{
            return false,errors.New("FI C1: full-backlog candidate opt-in without Security candidate")
        }
        return false,nil
    }
    if !privateC1Enabled() {
        return false,errors.New("FI C1: Security candidate requires direct P6 private clone")
    }
    full:=os.Getenv("FI_W512_C1_FULL_BACKLOG")=="1"
    prefix:=os.Getenv("FI_C1_DEV_PREFIX8")=="1"
    if full&& !prefix && fullOptIn=="1" &&
        os.Getenv("FI_W512_C1_GROUP_GIB")=="4" &&
        os.Getenv("FI_W512_C1_STOP_WINDOWS")==""{
        return true,nil
    }
    if !full&&prefix && fullOptIn!="1"{
        return true,nil
    }
    return false,errors.New("FI C1: Security candidate requires exact private 8GiB prefix or explicit unbounded 4GiB-group full-backlog opt-in")
}

const privateC1FamilyIdleTimeout = 30*time.Second
const privateC1FamilyIdlePollInterval = time.Second
type privateP6Lane struct{
    limit privateP6Limits
    pending []privateP6Record
    bytes int64
    handoffs int64
    records int64
    capacityHandoffs int64
    ageHandoffs int64 // reserved historical field; no age-driven flushes
    idleHandoffs int64
    dependencyHandoffs int64
    finalHandoffs int64
    peakRows int
    peakBytes int64
    lastReceivedAt time.Time
}
type privateP6Buffers struct{
    sink privateP6SQLHandoff
    window int
    lastBatch int
    lastOrdinal int64
    source privateP6Lane
    lanes [privateP6FamilyCount]privateP6Lane
    total int64
    inserted int64
    idleTimeout time.Duration
    finished bool
    failed error
}

func newPrivateP6Buffers(window int,sink privateP6SQLHandoff)(*privateP6Buffers,error){
    if window<1 || sink==nil{return nil,errors.New("FI P6: private window and SQL transaction sink required")}
    b:=&privateP6Buffers{window:window,sink:sink,lastBatch:-1,
        idleTimeout:privateC1FamilyIdleTimeout}
    // Exact profile bounds; no unbounded per-family memory. A source record
    // larger than one lane byte ceiling goes as ONE admitted item (bounded
    // by existing P5 global 256 MiB raw-record admission and source caps).
    b.source.limit=privateP6Limits{rows:8192,bytes:64<<20}
    b.lanes[privateP6Security].limit=privateP6Limits{rows:4096,bytes:16<<20}
    experimental,err:=privateC1Security8GiBExperiment()
    if err!=nil{return nil,err}
    if experimental{
        b.lanes[privateP6Security].limit=privateP6Limits{rows:8192,bytes:32<<20}
    }
    b.lanes[privateP6File].limit=privateP6Limits{rows:8192,bytes:32<<20}
    b.lanes[privateP6Coverage].limit=privateP6Limits{rows:512,bytes:8<<20}
    b.lanes[privateP6USN].limit=privateP6Limits{rows:512,bytes:8<<20}
    b.lanes[privateP6Other].limit=privateP6Limits{rows:512,bytes:8<<20}
    return b,nil
}

func privateP6ShouldFlush(l *privateP6Lane,incoming int64)bool{
    return len(l.pending)>0 &&
        (len(l.pending)>=l.limit.rows ||
            incoming>l.limit.bytes-l.bytes)
}
func privateP6Full(l *privateP6Lane)bool{
    return len(l.pending)>=l.limit.rows || l.bytes>=l.limit.bytes
}
func privateP6Enqueue(l *privateP6Lane,row privateP6Record){
    // Reset ONLY this family's inactivity clock upon actual reception.
    l.lastReceivedAt=time.Now()
    l.pending=append(l.pending,row)
    l.bytes+=int64(row.prepared.RecordBytes)
    if len(l.pending)>l.peakRows{l.peakRows=len(l.pending)}
    if l.bytes>l.peakBytes{l.peakBytes=l.bytes}
}

func (b *privateP6Buffers) Add(ctx context.Context,row privateP6Record)error{
    if b==nil||ctx==nil||b.sink==nil||b.finished||b.failed!=nil{
        return errors.New("FI P6: invalid or previously failed window buffer")
    }
    if err:=ctx.Err();err!=nil{b.failed=err;return err}
    family,err:=privateP6KindFamily(row.prepared.Record.RecordKind)
    if err!=nil{b.failed=err;return err}
    if !row.valid() ||
        row.signedBatchIndex<b.lastBatch ||
        (row.signedBatchIndex==b.lastBatch && row.ordinal<=b.lastOrdinal){
        b.failed=errors.New("FI P6: invalid signed identity, bytes or original record order")
        return b.failed
    }
    // Flush the shared source identity ledger before it exceeds its own
    // capacity. Source rows are inserted in true signed order, so USN's
    // established preceding-source-record-id relation still works.
    src:=&b.source
    if privateP6ShouldFlush(src,int64(row.prepared.RecordBytes)){
        if err=b.flushSource(ctx);err!=nil{return err}
    }
    privateP6Enqueue(src,row)
    b.inserted++ // admitted, not yet SQL-committed
    if privateP6Full(src){
        if err=b.flushSource(ctx);err!=nil{return err}
    }
    lane:=&b.lanes[family]
    if privateP6ShouldFlush(lane,int64(row.prepared.RecordBytes)){
        if err=b.flushFamily(ctx,family,"capacity");err!=nil{return err}
    }
    privateP6Enqueue(lane,row)
    b.total++
    b.lastBatch,b.lastOrdinal=row.signedBatchIndex,row.ordinal
    if privateP6Full(lane){
        if err=b.flushFamily(ctx,family,"capacity");err!=nil{return err}
    }
    return nil
}

// flushIdleFamilies runs only on the SAME consumer goroutine that owns Add.
// The independent one-second ticker in the continuous Preparation consumer
// invokes it even when no records arrive. No shared buffer locks or timer
// callbacks can race the ordered source/SQL handoff path.
func(b *privateP6Buffers) flushIdleFamilies(ctx context.Context,now time.Time)error{
    if b==nil||ctx==nil||b.finished||b.failed!=nil{
        return errors.New("FI C1 Family Processing: idle flush on inactive buffer")
    }
    if err:=ctx.Err();err!=nil{return err}
    for _,f:=range []privateP6Family{
        privateP6File,privateP6USN,privateP6Coverage,privateP6Other,privateP6Security,
    }{
        lane:=&b.lanes[f]
        if len(lane.pending)==0||lane.lastReceivedAt.IsZero(){continue}
        idle:=now.Sub(lane.lastReceivedAt)
        if idle<b.idleTimeout{continue}
        rows,bytes:=len(lane.pending),lane.bytes
        if err:=b.flushFamily(ctx,f,"idle");err!=nil{return err}
        fmt.Printf("FI C1 FAMILY PROCESSING IDLE FLUSH utc=%s family=%s idle=%s timeout=%s buffered_rows=%d buffered_bytes=%d trigger=inactivity no_batch_flush=true no_group_flush=true verifier_independent=true\n",
            now.UTC().Format(time.RFC3339Nano),privateP6FamilyNames[f],idle,
            b.idleTimeout,rows,bytes)
    }
    return nil
}

func(b *privateP6Buffers) flushSource(ctx context.Context)error{
    l:=&b.source
    if len(l.pending)==0{return nil}
    if err:=b.sink.Source(ctx,l.pending);err!=nil{
        b.failed=fmt.Errorf("FI P6: signed source ledger SQL failed: %w",err)
        return b.failed
    }
    l.records+=int64(len(l.pending))
    l.handoffs++
    l.pending=nil
    l.bytes=0
    l.lastReceivedAt=time.Time{}
    return nil
}

func(b *privateP6Buffers) flushFamily(ctx context.Context,f privateP6Family,reason string)error{
    if f>=privateP6FamilyCount{return errors.New("FI P6: unknown flush family")}
    lane:=&b.lanes[f]
    if len(lane.pending)==0{return nil}
    // A relational parent is a prerequisite of every typed child. This is
    // NOT a family flush: insert the single shared SOURCE identity ledger.
    if err:=b.flushSource(ctx);err!=nil{return err}
    // NTFS identities must exist before USN observations can bind to them.
    // No Security, Coverage or Other drain is allowed as a side effect.
    if f==privateP6USN && len(b.lanes[privateP6File].pending)>0{
        if err:=b.flushFamily(ctx,privateP6File,"dependency");err!=nil{return err}
    }
    // Shared SQL workers commit jobs independently. A File handoff must
    // become SQL-visible before dependent USN starts; other families
    // remain queued and are not drained by this dependency.
    if f==privateP6USN {
        // C1's ordered USN dispatcher snapshots and awaits EVERY earlier
        // File SQL broadcast fence off the main Preparation consumer.
        // Ordinary P6 sinks still enforce their synchronous File barrier.
        async,ok:=b.sink.(interface{AsyncUSNDependencies() bool})
        if !ok||!async.AsyncUSNDependencies(){
            if wait,ok:=b.sink.(interface{WaitFamily(context.Context,privateP6Family)error});ok{
                if err:=wait.WaitFamily(ctx,privateP6File);err!=nil{
                    b.failed=fmt.Errorf("FI P6 direct: File prerequisite commit: %w",err)
                    return b.failed
                }
            }
        }
    }
    if err:=b.sink.Family(ctx,f,lane.pending);err!=nil{
        b.failed=fmt.Errorf("FI P6: %s relational SQL handoff (%s): %w",
            privateP6FamilyNames[f],reason,err)
        return b.failed
    }
    lane.records+=int64(len(lane.pending))
    lane.handoffs++
    switch reason{
    case "capacity":lane.capacityHandoffs++
    case "idle":lane.idleHandoffs++
    case "dependency":lane.dependencyHandoffs++
    case "end-of-input":lane.finalHandoffs++
    default:panic("FI P6: unsupported flush reason")
    }
    lane.pending=nil
    lane.bytes=0
    lane.lastReceivedAt=time.Time{}
    return nil
}

// This is the only unconditional drain at the true end of signed input.
// Signed batch, K32 and W512 reporting boundaries do NOT call Finish.
// All five families must ACK before a typed completion marker can advance.
func(b *privateP6Buffers) Finish(ctx context.Context)error{
    if b==nil||ctx==nil||b.finished||b.failed!=nil{return errors.New("FI P6: invalid final window barrier")}
    if err:=b.flushSource(ctx);err!=nil{return err}
    // File before USN is a real relational prerequisite, not an
    // arbitrary family transition. Other families are independent.
    for _,f:=range []privateP6Family{
        privateP6Security,privateP6File,privateP6Coverage,privateP6USN,privateP6Other,
    }{
        if err:=b.flushFamily(ctx,f,"end-of-input");err!=nil{return err}
    }
    // P6's original SQL coordinator was synchronous. C1 waits for all five
    // shared worker commits across all five families before signed input completes.
    if wait,ok:=b.sink.(interface{WaitAll(context.Context)error});ok{
        if err:=wait.WaitAll(ctx);err!=nil{
            b.failed=fmt.Errorf("FI P6 direct: five-family commit barrier: %w",err)
            return b.failed
        }
    }
    var complete int64
    for f:=range b.lanes{
        l:=&b.lanes[f]
        if len(l.pending)!=0||l.bytes!=0 {
            return errors.New("FI P6: typed commit barrier has unfinished family work")
        }
        complete+=l.records
    }
    if complete!=b.total || b.source.records!=b.inserted ||
        b.inserted!=b.total || len(b.source.pending)!=0{
        return fmt.Errorf("FI P6: incomplete source/relational accounting source=%d typed=%d admitted=%d",
            b.source.records,complete,b.total)
    }
    b.finished=true
    fmt.Printf("FI P6 SOURCE LEDGER window=%d records=%d copy_handoffs=%d bytes_limit=%d complete=true\n",
        b.window,b.source.records,b.source.handoffs,b.source.limit.bytes)
    for family:=privateP6Family(0);family<privateP6FamilyCount;family++{
        lane:=&b.lanes[family]
        fmt.Printf("FI P6 FAMILY window=%d family=%s rows=%d handoffs=%d capacity=%d age=%d idle=%d dependency=%d final=%d peak_rows=%d peak_bytes=%d complete=true\n",
            b.window,privateP6FamilyNames[family],lane.records,lane.handoffs,
            lane.capacityHandoffs,lane.ageHandoffs,lane.idleHandoffs,lane.dependencyHandoffs,lane.finalHandoffs,
            lane.peakRows,lane.peakBytes)
    }
    fmt.Printf("FI C1 FINAL SOURCE AND FAMILY DRAIN window=%d source=%d typed=%d families=5 sql_writers=adaptive_shared clone_only=true completion=all_families\n",
        b.window,b.source.records,complete)
    return nil
}
