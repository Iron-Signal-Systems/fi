//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Development-only READ-ONLY evidence for interrupted C1 batch replay.
// A PostgreSQL committed SourceParent record is never inferred from tmpfs,
// an mTLS admission receipt or an unfinished SQL worker. The original signed
// JSONL bytes must be reread from immutable receiver custody before any
// eventual idempotent replay may use this map.
package recordingest

import (
    "bytes"
    "context"
    "errors"
    "fmt"
    "strings"
    "time"

    "github.com/Iron-Signal-Systems/fi/go/internal/c1handoff"
    "github.com/jackc/pgx/v5"
)

type C1RecoveryRowState struct {
    SourceRecordID int64
    ParentCommitted bool
    TypedRootCommitted bool
}

type c1PersistedSourceIdentity struct {
    ID int64
    Version,Kind,Scope string
    WrittenAt time.Time
    Bytes int64
    Digest []byte
    TypedRoot bool
}

func c1VerifyPersistedSourceIdentity(want privateP6Record,got c1PersistedSourceIdentity)(
    C1RecoveryRowState,error,
){
    var state C1RecoveryRowState
    if !want.valid(){return state,errors.New("C1 recovery: invalid signed prepared row")}
    if got.ID==0 {
        if got.TypedRoot{return state,errors.New("C1 recovery: typed root without SourceParent")}
        return state,nil
    }
    // Original LF-terminated JSONL may encode nanosecond timestamps.
    // PostgreSQL timestamptz stores microseconds, and the existing FI
    // projector uses that precision for written_at. Compare exactly at
    // PostgreSQL's stored precision; retain the FULL raw-record SHA-256
    // and byte count as the authoritative unrounded signed identity.
    if got.ID<0||got.Version!=want.prepared.Record.Version||
        got.Kind!=want.prepared.Record.RecordKind||
        got.Scope!=want.prepared.Record.ScopeID||
        got.Bytes!=int64(want.prepared.RecordBytes)||
        !got.WrittenAt.UTC().Equal(want.prepared.WrittenAtUTC.UTC().Truncate(time.Microsecond))||
        len(got.Digest)!=32||
        !bytes.Equal(got.Digest,want.prepared.RecordDigest[:]){
        return state,errors.New("C1 recovery: existing PostgreSQL source identity CONFLICTS with original signed record")
    }
    state.SourceRecordID=got.ID
    state.ParentCommitted=true
    state.TypedRootCommitted=got.TypedRoot
    return state,nil
}

// c1AuditCommittedRowStates batch-joins only explicitly supplied original
// (source_batch_id,ordinal) identities and checks every persisted digest.
// The query performs no SQL write and does not skip any SQL work itself.
// Reuse only in reconciliation; do NOT insert it in the clean P5/P6 hot path.
func c1AuditCommittedRowStates(ctx context.Context,tx pgx.Tx,
    rows []privateP6Record,targetSchema ...string)([]C1RecoveryRowState,error){
    if ctx==nil||tx==nil||len(rows)==0||len(rows)>c1handoff.MaxRows{
        return nil,errors.New("C1 recovery: bounded original signed rows and read-only SQL required")
    }
    schema:=privateProjectionSchema
    if len(targetSchema)>0 {
        if len(targetSchema)!=1||(targetSchema[0]!=""&&
            targetSchema[0]!=privateProjectionSchema&&
            targetSchema[0]!=c1GovernedPendingSchema&&
            targetSchema[0]!="fi"){
            return nil,errors.New("C1 recovery: unapproved read-only relational namespace")
        }
        if targetSchema[0]!=""{schema=targetSchema[0]}
    }
    batches:=make([]int64,len(rows))
    ordinals:=make([]int64,len(rows))
    type signedID struct{batch,ordinal int64}
    seen:=make(map[signedID]bool,len(rows))
    for i,r:=range rows {
        if !r.valid(){return nil,errors.New("C1 recovery: unvalidated original SourceParent")}
        key:=signedID{r.sourceBatchID,r.ordinal}
        if seen[key]{return nil,errors.New("C1 recovery: duplicate original signed record in reconciliation")}
        seen[key]=true
        batches[i]=r.sourceBatchID
        ordinals[i]=r.ordinal
    }
    // Every typed root is committed in the same PostgreSQL transaction as
    // its File/Security/USN/Coverage/Other mandatory children. Existence
    // alone does not replace complete signed-generation verification B.
    const query=`
WITH originals AS (
    SELECT batch_id,ordinal,position
    FROM unnest($1::bigint[],$2::bigint[]) WITH ORDINALITY
        AS input(batch_id,ordinal,position)
)
SELECT o.position,
       coalesce(sr.source_record_id,0)::bigint,
       coalesce(sr.version,''),
       coalesce(sr.record_kind,''),
       coalesce(sr.scope_id,''),
       coalesce(sr.written_at,timestamptz 'epoch'),
       coalesce(sr.record_bytes,0)::bigint,
       coalesce(sr.record_sha256,decode('','hex')),
       CASE sr.record_kind
         WHEN 'CollectorIdentity' THEN EXISTS (
            SELECT 1 FROM fi_recovery_projection.collector_identity x WHERE x.source_record_id=sr.source_record_id)
         WHEN 'DirectoryPrincipalSnapshot' THEN EXISTS (
            SELECT 1 FROM fi_recovery_projection.directory_principal_snapshot x WHERE x.source_record_id=sr.source_record_id)
         WHEN 'FileObservation' THEN EXISTS (
            SELECT 1 FROM fi_recovery_projection.file_observation x WHERE x.source_record_id=sr.source_record_id)
         WHEN 'LocalPrincipalSnapshot' THEN EXISTS (
            SELECT 1 FROM fi_recovery_projection.local_principal_snapshot x WHERE x.source_record_id=sr.source_record_id)
         WHEN 'NTFSCollectionError' THEN EXISTS (
            SELECT 1 FROM fi_recovery_projection.ntfs_collection_error x WHERE x.source_record_id=sr.source_record_id)
         WHEN 'SMBShareSnapshot' THEN EXISTS (
            SELECT 1 FROM fi_recovery_projection.smb_share_snapshot x WHERE x.source_record_id=sr.source_record_id)
         WHEN 'SupportingSourceCollectionError' THEN EXISTS (
            SELECT 1 FROM fi_recovery_projection.supporting_source_collection_error x WHERE x.source_record_id=sr.source_record_id)
         WHEN 'USNContinuityGap' THEN EXISTS (
            SELECT 1 FROM fi_recovery_projection.usn_continuity_gap x WHERE x.source_record_id=sr.source_record_id)
         WHEN 'USNObjectObservation' THEN EXISTS (
            SELECT 1 FROM fi_recovery_projection.usn_object_observation x WHERE x.source_record_id=sr.source_record_id)
         WHEN 'USNReadBoundary' THEN EXISTS (
            SELECT 1 FROM fi_recovery_projection.usn_read_boundary x WHERE x.source_record_id=sr.source_record_id)
         WHEN 'WindowsSecurityContinuityGap' THEN EXISTS (
            SELECT 1 FROM fi_recovery_projection.windows_security_continuity_gap x WHERE x.source_record_id=sr.source_record_id)
         WHEN 'WindowsSecurityCoverage' THEN EXISTS (
            SELECT 1 FROM fi_recovery_projection.windows_security_coverage x WHERE x.source_record_id=sr.source_record_id)
         WHEN 'WindowsSecurityEvent' THEN EXISTS (
            SELECT 1 FROM fi_recovery_projection.windows_security_event x WHERE x.source_record_id=sr.source_record_id)
         ELSE false
       END
FROM originals o
LEFT JOIN fi_recovery_projection.source_record sr
   ON sr.source_batch_id=o.batch_id AND sr.record_ordinal=o.ordinal
ORDER BY o.position`
    // Both options are compile-time whitelisted; no signed-frame input can
    // become a SQL identifier in the independent evidence readback.
    scopedQuery:=strings.ReplaceAll(query,privateProjectionSchema+".",schema+".")
    result,err:=tx.Query(ctx,scopedQuery,batches,ordinals)
    if err!=nil{return nil,err}
    state:=make([]C1RecoveryRowState,0,len(rows))
    for result.Next(){
        var position int64
        var existing c1PersistedSourceIdentity
        if err=result.Scan(&position,&existing.ID,&existing.Version,&existing.Kind,
            &existing.Scope,&existing.WrittenAt,&existing.Bytes,&existing.Digest,
            &existing.TypedRoot);err!=nil{break}
        if position!=int64(len(state)+1){
            err=errors.New("C1 recovery: duplicate or out-of-order persisted source identity")
            break
        }
        value,e:=c1VerifyPersistedSourceIdentity(rows[len(state)],existing)
        if e!=nil{err=fmt.Errorf("C1 recovery: signed row %d: %w",len(state),e);break}
        state=append(state,value)
    }
    if err==nil{err=result.Err()}
    result.Close()
    if err!=nil{return nil,err}
    if len(state)!=len(rows){return nil,errors.New("C1 recovery: incomplete PostgreSQL source evidence")}
    return state,nil
}

// InspectC1SoRPreviouslyCommittedRows is a public read-only entrypoint for
// an isolated C1 recovery test, not a production automatic replay API.
func InspectC1SoRPreviouslyCommittedRows(ctx context.Context,dsn string,
    originals []privateP6Record)([]C1RecoveryRowState,error){
    if ctx==nil||len(originals)==0{return nil,errors.New("C1 recovery: signed source records required")}
    conn,_,err:=openC1SoRLocalSQL(ctx,dsn,"")
    if err!=nil{return nil,err}
    defer conn.Close(context.Background())
    tx,err:=conn.BeginTx(ctx,pgx.TxOptions{IsoLevel:pgx.RepeatableRead,AccessMode:pgx.ReadOnly})
    if err!=nil{return nil,err}
    defer tx.Rollback(context.Background())
    state,err:=c1AuditCommittedRowStates(ctx,tx,originals)
    if err!=nil{return nil,err}
    if err=tx.Commit(ctx);err!=nil{return nil,err}
    return state,nil
}

// c1PartitionRecoveredHandoff constructs a fail-closed replay admission
// plan; it does NOT execute SQL or mark any record committed. For Source,
// a proven persisted parent can be skipped; for one of the five typed
// families, only the proven typed root can be skipped. Every skipped row
// must already have passed c1VerifyPersistedSourceIdentity against the
// original signed record and will later need a durable C1 readiness credit.
type c1RecoveredHandoffPlan struct {
    AlreadyCommitted []privateP6Record
    MustWrite []privateP6Record
}
func c1PartitionRecoveredHandoff(kind c1handoff.Kind,
    rows []privateP6Record,states []C1RecoveryRowState)(
    c1RecoveredHandoffPlan,error,
){
    var out c1RecoveredHandoffPlan
    if kind<c1handoff.Source||kind>c1handoff.Other||
        len(rows)==0||len(rows)!=len(states)||len(rows)>c1handoff.MaxRows{
        return out,errors.New("C1 recovery: invalid bounded SourceParent/typed family replay")
    }
    seen:=make(map[[2]int64]bool,len(rows))
    for i,row:=range rows{
        if !row.valid(){return c1RecoveredHandoffPlan{},errors.New("C1 recovery: invalid signed input row")}
        key:=[2]int64{row.sourceBatchID,row.ordinal}
        if seen[key]{return c1RecoveredHandoffPlan{},errors.New("C1 recovery: repeated signed row in replay handoff")}
        seen[key]=true
        family,err:=privateP6KindFamily(row.prepared.Record.RecordKind)
        if err!=nil{return c1RecoveredHandoffPlan{},err}
        if kind!=c1handoff.Source&&kind!=c1handoff.Kind(family+2){
            return c1RecoveredHandoffPlan{},errors.New("C1 recovery: wrong original typed family")
        }
        state:=states[i]
        if state.TypedRootCommitted&&!state.ParentCommitted||
            state.ParentCommitted&&state.SourceRecordID<=0||
            !state.ParentCommitted&&state.SourceRecordID!=0{
            return c1RecoveredHandoffPlan{},errors.New("C1 recovery: impossible durable parent/typed evidence")
        }
        committed:=state.ParentCommitted
        if kind!=c1handoff.Source{committed=state.TypedRootCommitted}
        if committed {
            out.AlreadyCommitted=append(out.AlreadyCommitted,row)
        }else{
            out.MustWrite=append(out.MustWrite,row)
        }
    }
    return out,nil
}
