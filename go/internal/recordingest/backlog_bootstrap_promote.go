// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// BootstrapPromoteVerifiedBacklogToEmptySoR is an opt-in, OWNER-PRIVILEGED
// candidate for the FIRST accepted FI generation in a completely empty
// canonical relational SoR. It is not wired to a production service.
//
// It avoids re-reading signed JSONL and rerunning the 49-table projectors.
// Instead, after independent private custody/typed verification, it copies
// all 48 historical tables from validated private SQL in FK order, preserving
// their numeric IDs, and atomically commits the Accepted journal entry.
//
// A populated authoritative SoR requires a DIFFERENT promotion algorithm:
// shared NTFS identities must be deduplicated and all generated ID/FK values
// remapped. This implementation *never* attempts that. It fails closed if
// any canonical non-journal table contains rows.
//
// Publisher MUST have table lock and sequence UPDATE privileges; ordinary
// fi_ingest intentionally does not. Private and canonical tables are locked
// to prevent a concurrent mutation during the independent final verifier.
// This path preserves required constraints/indexes; no synchronous-commit,
// WAL, durability or integrity settings are weakened.
func BootstrapPromoteVerifiedBacklogToEmptySoR(
	ctx context.Context,
	verifier, publisher *pgx.Conn,
	g *PreparedGeneration,
	limits BacklogWindowLimits,
	attemptID string,
) (IngestResult,error) {
	var empty IngestResult
	if ctx==nil || verifier==nil || publisher==nil || verifier==publisher ||
		g==nil || attemptID=="" {return empty,errors.New("FI SoR bootstrap: complete authenticated inputs and distinct SQL connections required")}
	if err:=ctx.Err();err!=nil{return empty,err}
	desc:=g.Receipt.Descriptor
	if desc.SourceID=="" || desc.GenerationID=="" || g.ReceiptSHA256=="" {
		return empty,errors.New("FI SoR bootstrap: missing signed generation identity")
	}
	started:=time.Now()
	// Retain the canonical Started record outside the publication transaction.
	// An interrupted/rolled-back attempt is never mislabeled Accepted.
	// A publisher without owner/table-lock/sequence rights will fail closed.
	// Do not enable this candidate in a service until isolated acceptance.
	if err:=WriteAttemptStarted(ctx,publisher,attemptID,desc.SourceID,desc.GenerationID);err!=nil{
		return empty,fmt.Errorf("FI SoR bootstrap: journal start: %w",err)
	}
	tx,err:=publisher.BeginTx(ctx,pgx.TxOptions{IsoLevel:pgx.ReadCommitted})
	if err!=nil{return empty,err}
	defer tx.Rollback(context.Background())
	if _,err=tx.Exec(ctx,"SET LOCAL lock_timeout = '5s'");err!=nil{return empty,err}
	var who,db string
	if err=tx.QueryRow(ctx,"SELECT current_user,current_database()").Scan(&who,&db);err!=nil{return empty,err}
	if db!="fi" || who=="" {return empty,errors.New("FI SoR bootstrap: unexpected SQL identity")}
	canonical,err:=bootstrapListTables(ctx,tx,"fi")
	if err!=nil{return empty,err}
	private,err:=bootstrapListTables(ctx,tx,privateProjectionSchema)
	if err!=nil{return empty,err}
	// A strict 49-table match, including the journal, prevents skipping
	// a new family silently when relational migrations evolve.
	if _,err=bootstrapSoRPromotionOrder(canonical,nil);err!=nil{return empty,err}
	if _,err=bootstrapSoRPromotionOrder(private,nil);err!=nil{return empty,err}
	fk,err:=bootstrapForeignKeys(ctx,tx)
	if err!=nil{return empty,err}
	order,err:=bootstrapSoRPromotionOrder(canonical,fk)
	if err!=nil{return empty,err}
	// Owner-level table locks are intentionally not available to the ordinary
	// ingest worker. Existing read-only SoR queries remain allowed.
	for _,name:=range canonical {
		target:=pgx.Identifier{"fi",name}.Sanitize()
		source:=pgx.Identifier{privateProjectionSchema,name}.Sanitize()
		if _,err=tx.Exec(ctx,"LOCK TABLE "+target+" IN SHARE ROW EXCLUSIVE MODE");err!=nil{
			return empty,fmt.Errorf("FI SoR bootstrap: canonical lock %s: %w",name,err)
		}
		if _,err=tx.Exec(ctx,"LOCK TABLE "+source+" IN SHARE MODE");err!=nil{
			return empty,fmt.Errorf("FI SoR bootstrap: private lock %s: %w",name,err)
		}
		if err=bootstrapCompareColumns(ctx,tx,name);err!=nil{return empty,err}
		if name!="ingest_journal" {
			var containsRows bool
			if err=tx.QueryRow(ctx,"SELECT EXISTS(SELECT 1 FROM "+target+" LIMIT 1)").Scan(&containsRows);err!=nil{return empty,err}
			if containsRows {return empty,fmt.Errorf("FI SoR bootstrap: canonical %s is populated; remapped incremental promotion required",name)}
		}
	}
	for _,name:=range []string{"verified_artifact_window","source_window","typed_window","pending_source_record"}{
		if _,err=tx.Exec(ctx,"LOCK TABLE "+pgx.Identifier{"fi_recovery",name}.Sanitize()+" IN SHARE MODE");err!=nil{return empty,err}
	}
	var privateGenerations int64
	var sourceMatched bool
	if err=tx.QueryRow(ctx,`SELECT count(*),
 coalesce(bool_and(source_id=$1 AND generation_id=$2),false)
 FROM fi_recovery_projection.recorded_generation`,desc.SourceID,desc.GenerationID).Scan(&privateGenerations,&sourceMatched);err!=nil{return empty,err}
	if privateGenerations!=1 || !sourceMatched {
		return empty,errors.New("FI SoR bootstrap: private projection is not one exact signed generation")
	}
	for _,name:=range []string{"ntfs_volume","governed_root"}{
		var unrelated bool
		q:="SELECT EXISTS(SELECT 1 FROM "+pgx.Identifier{privateProjectionSchema,name}.Sanitize()+" WHERE source_id<>$1 LIMIT 1)"
		if err=tx.QueryRow(ctx,q,desc.SourceID).Scan(&unrelated);err!=nil{return empty,err}
		if unrelated{return empty,errors.New("FI SoR bootstrap: unrelated private identity objects present")}
	}
	var privateJournal bool
	if err=tx.QueryRow(ctx,"SELECT EXISTS(SELECT 1 FROM fi_recovery_projection.ingest_journal LIMIT 1)").Scan(&privateJournal);err!=nil{return empty,err}
	if privateJournal{return empty,errors.New("FI SoR bootstrap: unexpected provisional ingest journal rows")}

	// Ensure all required sequence privileges before the FIRST bulk table
	// insertion. setval is essential: preserved IDs must not collide with
	// the next normal canonical generation after bootstrap publication.
	type seqSpec struct{table,col,seq string}
	var sequences []seqSpec
	for table,col:=range bootstrapIdentityColumns {
		var seq *string
		if err=tx.QueryRow(ctx,"SELECT pg_get_serial_sequence($1,$2)","fi."+table,col).Scan(&seq);err!=nil{return empty,err}
		if seq==nil || *seq==""{return empty,fmt.Errorf("FI SoR bootstrap: missing identity sequence %s.%s",table,col)}
		var updateAllowed bool
		if err=tx.QueryRow(ctx,"SELECT has_sequence_privilege(current_user,$1::regclass,'UPDATE')",*seq).Scan(&updateAllowed);err!=nil{return empty,err}
		if !updateAllowed{return empty,fmt.Errorf("FI SoR bootstrap: sequence UPDATE privilege missing: %s",*seq)}
		sequences=append(sequences,seqSpec{table:table,col:col,seq:*seq})
	}
	// The reader performs the existing full typed/source/custody verification
	// while writer-side locks prevent further private mutation.
	verifyStarted:=time.Now()
	verified,err:=VerifyCompleteBacklogTypedGeneration(ctx,verifier,g,limits)
	if err!=nil{return empty,fmt.Errorf("FI SoR bootstrap: complete private proof required: %w",err)}
	if verified.SourceID!=desc.SourceID || verified.GenerationID!=desc.GenerationID ||
		verified.ReceiptSHA256!=g.ReceiptSHA256 || verified.Records!=g.Receipt.RecordCount ||
		verified.DataBytes!=g.Receipt.DataBytes {
		return empty,errors.New("FI SoR bootstrap: verified source identity/count mismatch")
	}
	verifyTime:=time.Since(verifyStarted)
	var sourceCount,relationRows int64
	copyStarted:=time.Now()
	for _,name:=range order {
		target:=pgx.Identifier{"fi",name}.Sanitize()
		source:=pgx.Identifier{privateProjectionSchema,name}.Sanitize()
		// OVERRIDING SYSTEM VALUE retains exact private identities. The
		// precondition that canonical history is empty avoids all PK/FK
		// remapping and cross-generation NTFS merge ambiguity.
		sql:="INSERT INTO "+target+" OVERRIDING SYSTEM VALUE SELECT * FROM "+source
		tag,copyErr:=tx.Exec(ctx,sql)
		if copyErr!=nil {return empty,fmt.Errorf("FI SoR bootstrap: %s relational promotion: %w",name,copyErr)}
		relationRows+=tag.RowsAffected()
		if name=="source_record" {sourceCount=tag.RowsAffected()}
	}
	copyTime:=time.Since(copyStarted)
	if sourceCount!=int64(verified.Records) {return empty,fmt.Errorf("FI SoR bootstrap: source counts %d != signed %d",sourceCount,verified.Records)}
	for _,seq:=range sequences {
		target:=pgx.Identifier{"fi",seq.table}.Sanitize()
		column:=pgx.Identifier{seq.col}.Sanitize()
		var maxID *int64
		if err=tx.QueryRow(ctx,"SELECT max("+column+") FROM "+target).Scan(&maxID);err!=nil{return empty,err}
		if maxID==nil {continue}
		// setval is non-transactional. On failed COMMIT it can leave only
		// sequence gaps, never Accepted history or partial relational rows.
		_,err=tx.Exec(ctx,`SELECT setval($1::regclass,
GREATEST($2::bigint,COALESCE((
  SELECT last_value FROM pg_sequences
  WHERE schemaname='fi'
    AND sequencename=(SELECT relname FROM pg_class WHERE oid=$1::regclass)
),0::bigint)),true)`,seq.seq,*maxID)
		if err!=nil{return empty,fmt.Errorf("FI SoR bootstrap: advance identity %s: %w",seq.table,err)}
	}
	var acceptedGenerationID int64
	if err=tx.QueryRow(ctx,`SELECT recorded_generation_id FROM fi.recorded_generation
 WHERE source_id=$1 AND generation_id=$2`,desc.SourceID,desc.GenerationID).Scan(&acceptedGenerationID);err!=nil{
		return empty,fmt.Errorf("FI SoR bootstrap: published generation ID lookup: %w",err)
	}
	transfer,err:=decodeHex(g.Receipt.TransferSHA256,32,true,"backlog.bootstrap.transfer_sha256")
	if err!=nil{return empty,err}
	if _,err=tx.Exec(ctx,`
INSERT INTO fi.ingest_journal (
 attempt_id,event_sequence,source_id,generation_id,transfer_sha256,outcome,stage,records_seen,records_committed,ingest_version
) VALUES ($1,2,$2,$3,$4,'Accepted','AuthoritativeRecord',$5,$5,$6)`,
	attemptID,desc.SourceID,desc.GenerationID,transfer,int64(verified.Records),IngestVersion);err!=nil{
		return empty,fmt.Errorf("FI SoR bootstrap: atomic Accepted journal: %w",err)
	}
	commitStarted:=time.Now()
	if err=tx.Commit(ctx);err!=nil{return empty,fmt.Errorf("FI SoR bootstrap: commit indeterminate without read-back: %w",err)}
	commitTime:=time.Since(commitStarted)
	result:=IngestResult{
		AttemptID:attemptID,SourceID:desc.SourceID,GenerationID:desc.GenerationID,
		TransferSHA256:g.Receipt.TransferSHA256,ReceiptSHA256:g.ReceiptSHA256,
		Batches:len(g.Batches),DataBytes:g.Receipt.DataBytes,
		RecordsSeen:int64(verified.Records),RecordsCommitted:int64(verified.Records),
		RecordedGenerationID:acceptedGenerationID,Outcome:"Accepted",
	}
	fmt.Printf("FI SOR BOOTSTRAP PROMOTED source=%s generation=%s records=%d relational_rows=%d private_verify=%s sql_copy=%s commit=%s total=%s\n",
		desc.SourceID,desc.GenerationID,verified.Records,relationRows,
		verifyTime.Round(time.Millisecond),copyTime.Round(time.Millisecond),
		commitTime.Round(time.Millisecond),time.Since(started).Round(time.Millisecond))
	return result,nil
}

type bootstrapColumn struct{ name,typeName string;notNull bool;identity,generated string }
func bootstrapListTables(ctx context.Context,tx pgx.Tx,schema string)([]string,error){
	rows,err:=tx.Query(ctx,`SELECT c.relname FROM pg_class c
 JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname=$1 AND c.relkind='r' ORDER BY c.relname`,schema)
	if err!=nil{return nil,err}
	defer rows.Close()
	var out []string
	for rows.Next(){var n string;if err=rows.Scan(&n);err!=nil{return nil,err};out=append(out,n)}
	return out,rows.Err()
}
func bootstrapForeignKeys(ctx context.Context,tx pgx.Tx)([][2]string,error){
	rows,err:=tx.Query(ctx,`SELECT child.relname,parent.relname
 FROM pg_constraint fk
 JOIN pg_class child ON child.oid=fk.conrelid
 JOIN pg_namespace cn ON cn.oid=child.relnamespace
 JOIN pg_class parent ON parent.oid=fk.confrelid
 JOIN pg_namespace pn ON pn.oid=parent.relnamespace
 WHERE fk.contype='f' AND cn.nspname='fi' AND pn.nspname='fi'
 ORDER BY child.relname,parent.relname`)
	if err!=nil{return nil,err}
	defer rows.Close()
	var out [][2]string
	for rows.Next(){var a,b string;if err=rows.Scan(&a,&b);err!=nil{return nil,err};out=append(out,[2]string{a,b})}
	return out,rows.Err()
}
func bootstrapReadColumns(ctx context.Context,tx pgx.Tx,schema,table string)([]bootstrapColumn,error){
	rows,err:=tx.Query(ctx,`SELECT a.attname,format_type(a.atttypid,a.atttypmod),
 a.attnotnull,a.attidentity::text,a.attgenerated::text
 FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid
 JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname=$1 AND c.relname=$2 AND a.attnum>0 AND NOT a.attisdropped
 ORDER BY a.attnum`,schema,table)
	if err!=nil{return nil,err}
	defer rows.Close()
	var cols []bootstrapColumn
	for rows.Next(){
		var c bootstrapColumn
		if err=rows.Scan(&c.name,&c.typeName,&c.notNull,&c.identity,&c.generated);err!=nil{return nil,err}
		cols=append(cols,c)
	}
	return cols,rows.Err()
}
func bootstrapCompareColumns(ctx context.Context,tx pgx.Tx,table string)error{
	a,err:=bootstrapReadColumns(ctx,tx,"fi",table);if err!=nil{return err}
	b,err:=bootstrapReadColumns(ctx,tx,privateProjectionSchema,table);if err!=nil{return err}
	if len(a)==0 || len(a)!=len(b) {return fmt.Errorf("FI SoR bootstrap: %s column-count mismatch",table)}
	for i:=range a {if a[i]!=b[i] {return fmt.Errorf("FI SoR bootstrap: %s column %d differs from canonical schema",table,i)}}
	return nil
}
