// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
 "context"
 "errors"
 "fmt"
 "strings"
 "time"

 "github.com/jackc/pgx/v5"
)

// PromoteVerifiedBacklogToPopulatedSoR is the guarded, single-worker SQL
// promotion candidate for a previously populated authoritative SoR.
//
// Unlike IngestPreparedGeneration, this uses only independently verified
// private relational rows. Six database-generated identity families are
// remapped. NTFS volume/object/governed-root identities are deduplicated
// against existing canonical natural keys; source generation/batch/record IDs
// are always newly allocated. All 48 historical tables and the Accepted
// journal become visible in ONE PostgreSQL transaction.
//
// This function is intentionally NOT used by the production daemon yet:
// first validate rollback, foreign-key remaps, mixed family rows, exact retry,
// and performance against an isolated copy of the real signed backlog.
// The current canonical replay remains the fail-closed fallback.
func PromoteVerifiedBacklogToPopulatedSoR(
 ctx context.Context, verifier,publisher *pgx.Conn,
 g *PreparedGeneration, limits BacklogWindowLimits, attemptID string,
)(IngestResult,error){
 var zero IngestResult
 if ctx==nil || verifier==nil || publisher==nil || verifier==publisher ||
   g==nil || attemptID=="" {
  return zero,errors.New("FI SoR promotion: complete signed inputs and separate connections required")
 }
 if err:=ctx.Err();err!=nil{return zero,err}
 d:=g.Receipt.Descriptor
 if d.SourceID=="" || d.GenerationID=="" || g.ReceiptSHA256=="" ||
  g.Receipt.TransferSHA256=="" || len(g.Batches)==0 {
  return zero,errors.New("FI SoR promotion: generation identity and signed custody required")
 }
 started:=time.Now()
 // The retry check is merely an early read. The unique canonical generation
 // constraint remains the final arbiter if concurrent publishers race.
 var previousID int64
 var previousTransfer,previousReceipt []byte
 prevErr:=verifier.QueryRow(ctx,`SELECT recorded_generation_id,transfer_sha256,receipt_sha256
 FROM fi.recorded_generation WHERE source_id=$1 AND generation_id=$2`,
 d.SourceID,d.GenerationID).Scan(&previousID,&previousTransfer,&previousReceipt)
 if prevErr==nil {
  wantTransfer,err:=decodeHex(g.Receipt.TransferSHA256,32,true,"promote.retry.transfer_sha256")
  if err!=nil{return zero,err}
  wantReceipt,err:=decodeHex(g.ReceiptSHA256,32,true,"promote.retry.receipt_sha256")
  if err!=nil{return zero,err}
  if !bytesEqual(previousTransfer,wantTransfer)||!bytesEqual(previousReceipt,wantReceipt) {
   return zero,ErrGenerationConflict
  }
  var accepted int64
  if err=verifier.QueryRow(ctx,`SELECT count(*) FROM fi.ingest_journal
   WHERE source_id=$1 AND generation_id=$2 AND outcome='Accepted'
    AND transfer_sha256=$3 AND records_committed=$4`,
   d.SourceID,d.GenerationID,wantTransfer,int64(g.Receipt.RecordCount)).Scan(&accepted);err!=nil{
   return zero,err
  }
  if accepted!=1{return zero,errors.New("FI SoR promotion: canonical generation exists without exact Accepted journal")}
  return IngestResult{AttemptID:attemptID,SourceID:d.SourceID,GenerationID:d.GenerationID,
   TransferSHA256:g.Receipt.TransferSHA256,ReceiptSHA256:g.ReceiptSHA256,
   Batches:len(g.Batches),DataBytes:g.Receipt.DataBytes,
   RecordsSeen:int64(g.Receipt.RecordCount),RecordedGenerationID:previousID,
   Outcome:"AlreadyAccepted"},nil
 }
 if !errors.Is(prevErr,pgx.ErrNoRows){return zero,fmt.Errorf("FI SoR promotion: canonical identity preflight: %w",prevErr)}
 // Started is durable on its own; Accepted is inserted only at the end of
 // the giant relational transaction. A late FK/CHECK/IO failure rolls back
 // every authoritative row and leaves only an incomplete journal attempt.
 if err:=WriteAttemptStarted(ctx,publisher,attemptID,d.SourceID,d.GenerationID);err!=nil{
  return zero,fmt.Errorf("FI SoR promotion: durable journal start: %w",err)
 }
 tx,err:=publisher.BeginTx(ctx,pgx.TxOptions{IsoLevel:pgx.ReadCommitted})
 if err!=nil{return zero,err}
 defer tx.Rollback(context.Background())
 if _,err=tx.Exec(ctx,"SET LOCAL lock_timeout='5s'");err!=nil{return zero,err}
 var database,who string
 if err=tx.QueryRow(ctx,"SELECT current_database(),current_user").Scan(&database,&who);err!=nil{return zero,err}
 if database!="fi" || who=="" {return zero,errors.New("FI SoR promotion: unexpected PostgreSQL identity")}
 canonical,err:=bootstrapListTables(ctx,tx,"fi")
 if err!=nil{return zero,err}
 private,err:=bootstrapListTables(ctx,tx,privateProjectionSchema)
 if err!=nil{return zero,err}
 if _,err=bootstrapSoRPromotionOrder(canonical,nil);err!=nil{return zero,err}
 if _,err=bootstrapSoRPromotionOrder(private,nil);err!=nil{return zero,err}
 edges,err:=bootstrapForeignKeys(ctx,tx)
 if err!=nil{return zero,err}
 order,err:=bootstrapSoRPromotionOrder(canonical,edges)
 if err!=nil{return zero,err}
 for _,table:=range canonical{
  canonicalTable:=pgx.Identifier{"fi",table}.Sanitize()
  privateTable:=pgx.Identifier{privateProjectionSchema,table}.Sanitize()
  if _,err=tx.Exec(ctx,"LOCK TABLE "+canonicalTable+" IN SHARE ROW EXCLUSIVE MODE");err!=nil{
   return zero,fmt.Errorf("FI SoR promotion: canonical lock %s: %w",table,err)
  }
  if _,err=tx.Exec(ctx,"LOCK TABLE "+privateTable+" IN SHARE MODE");err!=nil{
   return zero,fmt.Errorf("FI SoR promotion: private lock %s: %w",table,err)
  }
  if err=bootstrapCompareColumns(ctx,tx,table);err!=nil{return zero,err}
 }
 for _,table:=range []string{"verified_artifact_window","source_window","typed_window","pending_source_record"}{
  if _,err=tx.Exec(ctx,"LOCK TABLE "+pgx.Identifier{"fi_recovery",table}.Sanitize()+" IN SHARE MODE");err!=nil{return zero,err}
 }
 var privateGenerations int64
 var matches bool
 err=tx.QueryRow(ctx,`SELECT count(*),
   coalesce(bool_and(source_id=$1 AND generation_id=$2),false)
   FROM fi_recovery_projection.recorded_generation`,d.SourceID,d.GenerationID).Scan(&privateGenerations,&matches)
 if err!=nil{return zero,err}
 if privateGenerations!=1 || !matches{return zero,errors.New("FI SoR promotion: private relational tables contain a different generation")}
 for _,table:=range []string{"ntfs_volume","governed_root"}{
  src:=pgx.Identifier{privateProjectionSchema,table}.Sanitize()
  var unrelated bool
  if err=tx.QueryRow(ctx,"SELECT EXISTS(SELECT 1 FROM "+src+" WHERE source_id<>$1)",d.SourceID).Scan(&unrelated);err!=nil{return zero,err}
  if unrelated{return zero,fmt.Errorf("FI SoR promotion: unrelated private %s",table)}
 }
 var privateJournal bool
 if err=tx.QueryRow(ctx,`SELECT EXISTS(SELECT 1 FROM fi_recovery_projection.ingest_journal)`).Scan(&privateJournal);err!=nil{return zero,err}
 if privateJournal{return zero,errors.New("FI SoR promotion: unexpected private journal")}
 var already bool
 if err=tx.QueryRow(ctx,`SELECT EXISTS(SELECT 1 FROM fi.recorded_generation
  WHERE source_id=$1 AND generation_id=$2)`,d.SourceID,d.GenerationID).Scan(&already);err!=nil{return zero,err}
 if already{return zero,errors.New("FI SoR promotion: concurrent generation accepted; retry for AlreadyAccepted")}

 // No private mutations can pass the SHARE locks during independent receipt,
 // joined-source, relational, coverage, and complete-window verification.
 verifyStarted:=time.Now()
 verified,err:=VerifyCompleteBacklogTypedGeneration(ctx,verifier,g,limits)
 if err!=nil{return zero,fmt.Errorf("FI SoR promotion: private signed generation not complete: %w",err)}
 if verified.SourceID!=d.SourceID || verified.GenerationID!=d.GenerationID ||
  verified.ReceiptSHA256!=g.ReceiptSHA256 || verified.Records!=g.Receipt.RecordCount ||
  verified.DataBytes!=g.Receipt.DataBytes {
  return zero,errors.New("FI SoR promotion: verified receipt/coverage/count mismatch")
 }
 verifyElapsed:=time.Since(verifyStarted)

 // All source/generated IDs receive NEW canonical sequence values. Natural
 // NTFS identities receive existing values where equal and new ones only
 // when absent; identity-method/containment conflicts are fatal.
 for table:=range bootstrapIdentityColumns{
  q:="CREATE TEMP TABLE "+sorPromotionMapSQL(table)+
   " (old_id bigint PRIMARY KEY,new_id bigint NOT NULL UNIQUE) ON COMMIT DROP"
  if _,err=tx.Exec(ctx,q);err!=nil{return zero,fmt.Errorf("FI SoR promotion: map %s: %w",table,err)}
 }
 var copied,sourceCount int64
 sqlStarted:=time.Now()
 for _,table:=range order{
  if sorPromotionNaturalTables[table] {
   added,mergeErr:=mergePrivateNaturalIdentity(ctx,tx,table)
   if mergeErr!=nil{return zero,mergeErr}
   copied+=added
   continue
  }
  if col,isIdentity:=bootstrapIdentityColumns[table];isIdentity{
   if err=allocateSoRIdentityMap(ctx,tx,table,col);err!=nil{return zero,err}
  }
  cols,colErr:=bootstrapReadColumns(ctx,tx,"fi",table)
  if colErr!=nil{return zero,colErr}
  if err=checkSoROptionalFKMaps(ctx,tx,table,cols);err!=nil{return zero,err}
  q,planErr:=compileSoRRemapSelect(table,cols)
  if planErr!=nil{return zero,planErr}
  var tag pgconnCommandTag
  if strings.Contains(q,"$1::timestamptz"){
   tag,err=execSoRPromotion(ctx,tx,q,time.Now().UTC())
  }else{
   tag,err=execSoRPromotion(ctx,tx,q)
  }
  if err!=nil{return zero,fmt.Errorf("FI SoR promotion: %s: %w",table,err)}
  var privateCount int64
  src:=pgx.Identifier{privateProjectionSchema,table}.Sanitize()
  if err=tx.QueryRow(ctx,"SELECT count(*) FROM "+src).Scan(&privateCount);err!=nil{return zero,err}
  if tag.RowsAffected()!=privateCount{
   return zero,fmt.Errorf("FI SoR promotion: mapped %s lost rows copied=%d original=%d",table,tag.RowsAffected(),privateCount)
  }
  copied+=privateCount
  if table=="source_record"{sourceCount=privateCount}
 }
 sqlElapsed:=time.Since(sqlStarted)
 if sourceCount!=int64(verified.Records){
  return zero,fmt.Errorf("FI SoR promotion: wrong source count %d != %d",sourceCount,verified.Records)
 }
 var newGenerationID int64
 err=tx.QueryRow(ctx,"SELECT new_id FROM "+sorPromotionMapSQL("recorded_generation")+" LIMIT 1").Scan(&newGenerationID)
 if err!=nil{return zero,err}
 transfer,err:=decodeHex(g.Receipt.TransferSHA256,32,true,"FI SoR promotion transfer_sha256")
 if err!=nil{return zero,err}
 if _,err=tx.Exec(ctx,`INSERT INTO fi.ingest_journal
 (attempt_id,event_sequence,source_id,generation_id,transfer_sha256,outcome,
 stage,records_seen,records_committed,ingest_version)
 VALUES ($1,2,$2,$3,$4,'Accepted','AuthoritativeRecord',$5,$5,$6)`,
 attemptID,d.SourceID,d.GenerationID,transfer,int64(verified.Records),IngestVersion);err!=nil{
  return zero,fmt.Errorf("FI SoR promotion: Accepted write: %w",err)
 }
 commitStart:=time.Now()
 if err=tx.Commit(ctx);err!=nil{
  return zero,fmt.Errorf("FI SoR promotion: commit outcome unknown; verify journal before retry: %w",err)
 }
 commitElapsed:=time.Since(commitStart)
 result:=IngestResult{AttemptID:attemptID,SourceID:d.SourceID,GenerationID:d.GenerationID,
  TransferSHA256:g.Receipt.TransferSHA256,ReceiptSHA256:g.ReceiptSHA256,
  Batches:len(g.Batches),DataBytes:g.Receipt.DataBytes,
  RecordsSeen:int64(verified.Records),RecordsCommitted:int64(verified.Records),
  RecordedGenerationID:newGenerationID,Outcome:"Accepted",
 }
 fmt.Printf("FI SOR REMAPPED PROMOTION source=%s generation=%s records=%d relational_rows=%d private_verify=%s sql_promote=%s commit=%s total=%s\n",
  d.SourceID,d.GenerationID,result.RecordsCommitted,copied,verifyElapsed.Round(time.Millisecond),
  sqlElapsed.Round(time.Millisecond),commitElapsed.Round(time.Millisecond),
  time.Since(started).Round(time.Millisecond))
 return result,nil
}

// Use a narrow type rather than encoding engine-specific integer types
// throughout the promotion code.
type pgconnCommandTag interface{RowsAffected() int64}
func execSoRPromotion(ctx context.Context,tx pgx.Tx,sql string,args ...any)(pgconnCommandTag,error){
 return tx.Exec(ctx,sql,args...)
}
func allocateSoRIdentityMap(ctx context.Context,tx pgx.Tx,table,col string)error{
 var seq *string
 if err:=tx.QueryRow(ctx,"SELECT pg_get_serial_sequence($1,$2)","fi."+table,col).Scan(&seq);err!=nil{return err}
 if seq==nil || *seq==""{return fmt.Errorf("FI SoR promotion: missing canonical sequence %s.%s",table,col)}
 var permitted bool
 if err:=tx.QueryRow(ctx,"SELECT has_sequence_privilege(current_user,$1::regclass,'USAGE')",*seq).Scan(&permitted);err!=nil{return err}
 if !permitted{return fmt.Errorf("FI SoR promotion: sequence USAGE denied for %s",table)}
 src:=pgx.Identifier{privateProjectionSchema,table}.Sanitize()
 colID:=pgx.Identifier{col}.Sanitize()
 q:="INSERT INTO "+sorPromotionMapSQL(table)+
  " (old_id,new_id) SELECT src."+colID+",nextval($1::regclass) FROM "+src+
  " AS src ORDER BY src."+colID
 if _,err:=tx.Exec(ctx,q,*seq);err!=nil{return fmt.Errorf("FI SoR promotion: generate %s IDs: %w",table,err)}
 return nil
}

func checkSoROptionalFKMaps(ctx context.Context,tx pgx.Tx,table string,cols []bootstrapColumn)error{
 src:=pgx.Identifier{privateProjectionSchema,table}.Sanitize()
 for _,c:=range cols{
  family,found:=sorPromotionFKMap[c.name]
  if !found || c.notNull{continue}
  col:=pgx.Identifier{c.name}.Sanitize()
  q:="SELECT EXISTS(SELECT 1 FROM "+src+" src LEFT JOIN "+sorPromotionMapSQL(family)+
   " AS map ON map.old_id=src."+col+
   " WHERE src."+col+" IS NOT NULL AND map.new_id IS NULL)"
  var missing bool
  if err:=tx.QueryRow(ctx,q).Scan(&missing);err!=nil{return err}
  if missing{return fmt.Errorf("FI SoR promotion: unmapped nullable FK in %s.%s",table,c.name)}
 }
 return nil
}

// The only three cross-generation shared identity tables. Integrity requires
// equality on their genuine natural keys AND their identity method versions.
// Canonical and private records remain immutable; ON CONFLICT never UPDATEs.
func mergePrivateNaturalIdentity(ctx context.Context,tx pgx.Tx,table string)(int64,error){
 switch table {
 case "ntfs_volume":return mergePrivateVolume(ctx,tx)
 case "ntfs_object":return mergePrivateObject(ctx,tx)
 case "governed_root":return mergePrivateRoot(ctx,tx)
 default:return 0,fmt.Errorf("FI SoR promotion: unexpected natural identity %q",table)
 }
}
func checkNaturalMapComplete(ctx context.Context,tx pgx.Tx,table string)(error){
 var sourceN,mappedN int64
 src:=pgx.Identifier{privateProjectionSchema,table}.Sanitize()
 if err:=tx.QueryRow(ctx,"SELECT count(*) FROM "+src).Scan(&sourceN);err!=nil{return err}
 if err:=tx.QueryRow(ctx,"SELECT count(*) FROM "+sorPromotionMapSQL(table)).Scan(&mappedN);err!=nil{return err}
 if sourceN!=mappedN{return fmt.Errorf("FI SoR promotion: incomplete natural identity map %s: %d/%d",table,mappedN,sourceN)}
 return nil
}
func mergePrivateVolume(ctx context.Context,tx pgx.Tx)(int64,error){
 sql:=`INSERT INTO fi.ntfs_volume(source_id,identity_method_version,volume_guid,volume_serial)
 SELECT source_id,identity_method_version,volume_guid,volume_serial
 FROM fi_recovery_projection.ntfs_volume
 ON CONFLICT ON CONSTRAINT ntfs_volume_identity_uq DO NOTHING`
 tag,err:=tx.Exec(ctx,sql)
 if err!=nil{return 0,err}
 mapSQL:=`INSERT INTO pg_temp.fi_promote_map_ntfs_volume(old_id,new_id)
 SELECT src.ntfs_volume_id,canon.ntfs_volume_id
 FROM fi_recovery_projection.ntfs_volume src JOIN fi.ntfs_volume canon
 ON src.source_id=canon.source_id AND src.volume_guid=canon.volume_guid
 AND src.volume_serial=canon.volume_serial
 WHERE src.identity_method_version=canon.identity_method_version`
 if _,err=tx.Exec(ctx,mapSQL);err!=nil{return 0,err}
 return tag.RowsAffected(),checkNaturalMapComplete(ctx,tx,"ntfs_volume")
}
func mergePrivateObject(ctx context.Context,tx pgx.Tx)(int64,error){
 sql:=`INSERT INTO fi.ntfs_object(ntfs_volume_id,identity_method_version,
  file_reference_number,sequence_number)
 SELECT mv.new_id,src.identity_method_version,src.file_reference_number,src.sequence_number
 FROM fi_recovery_projection.ntfs_object src
 JOIN pg_temp.fi_promote_map_ntfs_volume mv ON mv.old_id=src.ntfs_volume_id
 ON CONFLICT ON CONSTRAINT ntfs_object_identity_uq DO NOTHING`
 tag,err:=tx.Exec(ctx,sql);if err!=nil{return 0,err}
 mapSQL:=`INSERT INTO pg_temp.fi_promote_map_ntfs_object(old_id,new_id)
 SELECT src.ntfs_object_id,canon.ntfs_object_id
 FROM fi_recovery_projection.ntfs_object src
 JOIN pg_temp.fi_promote_map_ntfs_volume mv ON mv.old_id=src.ntfs_volume_id
 JOIN fi.ntfs_object canon ON canon.ntfs_volume_id=mv.new_id
 AND canon.file_reference_number=src.file_reference_number
 AND canon.sequence_number=src.sequence_number
 WHERE src.identity_method_version=canon.identity_method_version`
 if _,err=tx.Exec(ctx,mapSQL);err!=nil{return 0,err}
 return tag.RowsAffected(),checkNaturalMapComplete(ctx,tx,"ntfs_object")
}
func mergePrivateRoot(ctx context.Context,tx pgx.Tx)(int64,error){
 sql:=`INSERT INTO fi.governed_root(source_id,scope_id,containment_method_version,
  ntfs_volume_id,ntfs_object_id,requested_path_utf16le,resolved_path_utf16le)
 SELECT src.source_id,src.scope_id,src.containment_method_version,
 mv.new_id,mo.new_id,src.requested_path_utf16le,src.resolved_path_utf16le
 FROM fi_recovery_projection.governed_root src
 JOIN pg_temp.fi_promote_map_ntfs_volume mv ON mv.old_id=src.ntfs_volume_id
 JOIN pg_temp.fi_promote_map_ntfs_object mo ON mo.old_id=src.ntfs_object_id
 ON CONFLICT ON CONSTRAINT governed_root_identity_uq DO NOTHING`
 tag,err:=tx.Exec(ctx,sql);if err!=nil{return 0,err}
 mapSQL:=`INSERT INTO pg_temp.fi_promote_map_governed_root(old_id,new_id)
 SELECT src.governed_root_id,canon.governed_root_id
 FROM fi_recovery_projection.governed_root src
 JOIN pg_temp.fi_promote_map_ntfs_volume mv ON mv.old_id=src.ntfs_volume_id
 JOIN pg_temp.fi_promote_map_ntfs_object mo ON mo.old_id=src.ntfs_object_id
 JOIN fi.governed_root canon ON src.source_id=canon.source_id
  AND src.scope_id=canon.scope_id AND canon.ntfs_volume_id=mv.new_id
  AND canon.ntfs_object_id=mo.new_id
  AND canon.requested_path_utf16le=src.requested_path_utf16le
  AND canon.resolved_path_utf16le=src.resolved_path_utf16le
 WHERE src.containment_method_version=canon.containment_method_version`
 if _,err=tx.Exec(ctx,mapSQL);err!=nil{return 0,err}
 return tag.RowsAffected(),checkNaturalMapComplete(ctx,tx,"governed_root")
}
