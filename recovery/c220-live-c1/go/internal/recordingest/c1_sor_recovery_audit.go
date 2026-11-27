//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Read-only restart audit for C1. A lost tmpfs object is NOT a lost signed
// source record. PostgreSQL may have partially committed SourceParent and
// different typed families before power loss. Never replay or discard those
// commits until a verified per-batch relational prefix has been established.
package recordingest

import (
    "context"
    "encoding/hex"
    "errors"
    "fmt"
    "strings"

    "github.com/Iron-Signal-Systems/fi/go/internal/c1handoff"
    "github.com/jackc/pgx/v5"
)

// C1RecoveryBatchEvidence is an observational PostgreSQL snapshot, never a
// signed-custody replacement or a write authorization.
type C1RecoveryBatchEvidence struct {
    Index int
    BatchID string
    SourceBatchID int64
    SignedRecords int64
    SignedBytes int64
    ParentRows int64
    ParentDistinctOrdinals int64
    ParentBytes int64
    MinOrdinal int64
    MaxOrdinal int64
}

// C1RecoveryAuditReport is diagnostic until the complete partial-commit
// reconciler and original signed-custody comparison have been accepted.
// RelationalCompletePrefix excludes every batch lacking a typed root.
type C1RecoveryAuditReport struct {
    SourceID string
    GenerationID string
    ReceiptSHA256 string
    SignedBatches int
    SourceCompletePrefix int
    RelationalCompletePrefix int
    FirstUnresolvedBatch int
    TotalExistingParents int64
    DirtyTail bool
    // This is intentionally always false. A read-only SQL survey alone
    // cannot authorize replay of incomplete SourceParent/five-family work.
    AutomaticReplayAuthorized bool
}

// c1ClassifyRecoverySourcePrefix accepts only contiguous 1-based source
// ordinals and exact signed totals. Source prefix is not proof of typed
// projection or original signed JSONL digest identity.
func c1ClassifyRecoverySourcePrefix(evidence []C1RecoveryBatchEvidence)(
    prefix int,dirty bool,total int64,err error,
){
    seenUnfinished:=false
    for i,e:=range evidence{
        if e.Index!=i||e.SourceBatchID<=0||e.BatchID==""||
            e.SignedRecords<=0||e.SignedBytes<=0||
            e.ParentRows<0||e.ParentDistinctOrdinals<0||e.ParentBytes<0||
            e.ParentRows>e.SignedRecords||e.ParentBytes>e.SignedBytes{
            return 0,false,0,fmt.Errorf("C1 recovery: invalid signed parent evidence for batch %d",i)
        }
        total+=e.ParentRows
        if e.ParentRows==0{
            if e.ParentDistinctOrdinals!=0||e.ParentBytes!=0||
                e.MinOrdinal!=0||e.MaxOrdinal!=0{
                return 0,false,0,fmt.Errorf("C1 recovery: empty batch %d has contradictory source evidence",i)
            }
            seenUnfinished=true
            continue
        }
        // PostgreSQL UNIQUE(source_batch_id, record_ordinal) is expected;
        // still enforce DISTINCT and exact min/max on the audit snapshot.
        if e.ParentDistinctOrdinals!=e.ParentRows||e.MinOrdinal!=1||
            e.MaxOrdinal!=e.ParentRows{
            return 0,false,0,fmt.Errorf("C1 recovery: batch %d has missing, duplicated or noncontiguous source ordinals",i)
        }
        if seenUnfinished{
            return 0,false,0,fmt.Errorf("C1 recovery: source rows found after incomplete signed batch %d",i)
        }
        if e.ParentRows==e.SignedRecords {
            if e.ParentBytes!=e.SignedBytes{
                return 0,false,0,fmt.Errorf("C1 recovery: complete batch %d has mismatched signed bytes",i)
            }
            prefix=i+1
        }else{
            seenUnfinished=true
            dirty=true
        }
    }
    return prefix,dirty,total,nil
}


// c1FindReadOnlyTypedPrefix uses monotone committed typed-root evidence.
// A missing typed root is recoverable only after its original signed bytes
// and partial family SQL state are reconciled; other SQL errors fail closed.
func c1FindReadOnlyTypedPrefix(completeParents int,check func(int)error)(int,error){
    if completeParents<0||check==nil{
        return 0,errors.New("C1 recovery: missing relational coverage predicate")
    }
    low,high:=0,completeParents
    for low<high{
        mid:=low+(high-low+1)/2
        err:=check(mid)
        if err==nil{low=mid;continue}
        if !errors.Is(err,ErrSourceRecordRejected){
            return 0,fmt.Errorf("C1 recovery: read-only typed projection proof failed: %w",err)
        }
        high=mid-1
    }
    return low,nil
}

// AuditC1SoRPrivateRecovery uses one REPEATABLE READ / READ ONLY snapshot
// inside fi-sor. It has zero SQL writes, uses no RAM buffer, never invokes
// a P5/P6 flush, and explicitly does NOT authorize automatic replay.
func AuditC1SoRPrivateRecovery(ctx context.Context,dsn string,plan c1handoff.Frame,
    targetSchema ...string)(C1RecoveryAuditReport,error){
    var report C1RecoveryAuditReport
    schema,err:=sorPromotionSourceSchema(targetSchema...)
    if err!=nil{return report,err}
    if ctx==nil||plan.Kind!=c1handoff.Start {
        return report,errors.New("C1 recovery: authenticated original signed START required")
    }
    if err:=plan.Validate();err!=nil{return report,err}
    conn,_,err:=openC1SoRLocalSQL(ctx,dsn,"")
    if err!=nil{return report,err}
    defer conn.Close(context.Background())
    tx,err:=conn.BeginTx(ctx,pgx.TxOptions{IsoLevel:pgx.RepeatableRead,AccessMode:pgx.ReadOnly})
    if err!=nil{return report,err}
    defer tx.Rollback(context.Background())

    digest,e:=hex.DecodeString(plan.ReceiptSHA256)
    if e!=nil||len(digest)!=32{
        return report,errors.New("C1 recovery: signed receipt digest invalid")
    }
    var published bool
    if err=tx.QueryRow(ctx,`SELECT EXISTS(
        SELECT 1 FROM fi.recorded_generation
        WHERE source_id=$1 AND generation_id=$2)`,
        plan.SourceID,plan.GenerationID).Scan(&published);err!=nil{return report,err}
    if published{return report,errors.New("C1 recovery: generation already authoritative")}
    var generationID,storedRecords,storedBatches int64
    if err=tx.QueryRow(ctx,`SELECT recorded_generation_id,record_count,batch_count
        FROM `+pgx.Identifier{schema,"recorded_generation"}.Sanitize()+`
        WHERE source_id=$1 AND generation_id=$2 AND receipt_sha256=$3`,
        plan.SourceID,plan.GenerationID,digest).
        Scan(&generationID,&storedRecords,&storedBatches);err!=nil{
        // The PostgreSQL role, row visibility and receipt selection need
        // their own read-only evidence. Avoid flattening SQL ErrNoRows into
        // a misleading implication that the original signed receipt changed.
        if errors.Is(err,pgx.ErrNoRows){
            var visible,exact int64
            var role string
            auditErr:=tx.QueryRow(ctx,
                "SELECT current_user, count(*)::bigint, "+
                "count(*) FILTER (WHERE receipt_sha256=$3)::bigint FROM "+
                pgx.Identifier{schema,"recorded_generation"}.Sanitize()+
                " WHERE source_id=$1 AND generation_id=$2",
                plan.SourceID,plan.GenerationID,digest).Scan(&role,&visible,&exact)
            if auditErr!=nil{
                return report,fmt.Errorf("C1 recovery: exact Pending generation lookup failed; visibility audit: %w (initial: %v)",auditErr,err)
            }
            return report,fmt.Errorf("C1 recovery: signed Pending row not visible to role=%s schema=%s source_generation_matches=%d receipt_matches=%d: %w",
                role,schema,visible,exact,err)
        }
        return report,fmt.Errorf("C1 recovery: exact signed Pending generation metadata query: %w",err)
    }
    if generationID<=0||storedBatches!=int64(len(plan.BatchIDs))||storedRecords<=0{
        return report,errors.New("C1 recovery: original signed generation size/identity differs from private stage")
    }
    var generations int64
    if err=tx.QueryRow(ctx,"SELECT count(*) FROM "+pgx.Identifier{schema,"recorded_generation"}.Sanitize()).
        Scan(&generations);err!=nil{return report,err}
    if generations!=1{return report,errors.New("C1 recovery: unrelated private generation present")}

    // The query reads every original signed batch (including any verified
    // immutable seed). No row data, checksum, timestamp or SQL state is
    // modified by the audit.
    rows,err:=tx.Query(ctx,strings.ReplaceAll(`
SELECT sb.batch_id,sb.source_batch_id,sb.record_count,sb.data_bytes,
       count(sr.source_record_id)::bigint,
       count(DISTINCT sr.record_ordinal)::bigint,
       coalesce(sum(sr.record_bytes),0)::bigint,
       coalesce(min(sr.record_ordinal),0)::bigint,
       coalesce(max(sr.record_ordinal),0)::bigint
FROM fi_recovery_projection.source_batch sb
LEFT JOIN fi_recovery_projection.source_record sr
    ON sr.source_batch_id=sb.source_batch_id
WHERE sb.recorded_generation_id=$1
GROUP BY sb.batch_id,sb.source_batch_id,sb.record_count,sb.data_bytes
ORDER BY sb.batch_id`,privateProjectionSchema+".",schema+"."),generationID)
    if err!=nil{return report,err}
    evidence:=make([]C1RecoveryBatchEvidence,0,len(plan.BatchIDs))
    var signedRecords int64
    for rows.Next(){
        var x C1RecoveryBatchEvidence
        x.Index=len(evidence)
        if err=rows.Scan(&x.BatchID,&x.SourceBatchID,&x.SignedRecords,
            &x.SignedBytes,&x.ParentRows,&x.ParentDistinctOrdinals,
            &x.ParentBytes,&x.MinOrdinal,&x.MaxOrdinal);err!=nil{break}
        if x.Index>=len(plan.BatchIDs)||x.BatchID!=plan.BatchIDs[x.Index]{
            err=errors.New("C1 recovery: private source_batch order differs from original signed START")
            break
        }
        signedRecords+=x.SignedRecords
        evidence=append(evidence,x)
    }
    if err==nil{err=rows.Err()}
    rows.Close()
    if err!=nil{return report,err}
    if len(evidence)!=len(plan.BatchIDs)||signedRecords!=storedRecords{
        return report,errors.New("C1 recovery: incomplete signed source_batch plan or record sum")
    }
    var newRecords int64
    for i:=int(plan.StartBatchIndex);i<len(evidence);i++{
        newRecords+=evidence[i].SignedRecords
    }
    if newRecords!=plan.ExpectedRecords{
        return report,errors.New("C1 recovery: signed START does not match original private batch totals")
    }
    sourcePrefix,partialSource,parents,err:=c1ClassifyRecoverySourcePrefix(evidence)
    if err!=nil{return report,err}

    // A SourceParent row is NOT equivalent to completed typed projection.
    // The original 13-kind relational coverage checker proves only an
    // existing contiguous prefix, independent of the private P6 buffers.
    shadow:=privateProjectionTx{Tx:tx,schema:schema}
    typedPrefix,err:=c1FindReadOnlyTypedPrefix(sourcePrefix,func(mid int)error{
        originals:=make([]PreparedBatch,mid)
        for i:=0;i<mid;i++{originals[i].BatchID=evidence[i].BatchID}
        return verifyBacklogWindowProjectionCoverage(ctx,shadow,generationID,originals)
    })
    if err!=nil{return report,err}
    if err=tx.Commit(ctx);err!=nil{return report,err}
    report=C1RecoveryAuditReport{
        SourceID:plan.SourceID,GenerationID:plan.GenerationID,
        ReceiptSHA256:plan.ReceiptSHA256,SignedBatches:len(evidence),
        SourceCompletePrefix:sourcePrefix,RelationalCompletePrefix:typedPrefix,
        FirstUnresolvedBatch:typedPrefix,TotalExistingParents:parents,
        DirtyTail:partialSource||typedPrefix<sourcePrefix,
        AutomaticReplayAuthorized:false,
    }
    return report,nil
}
