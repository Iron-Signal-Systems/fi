// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, in the repository root LICENSE file.

package recordingest

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"os"
	"path/filepath"

	"github.com/jackc/pgx/v5"
)

const backlogSourceCopyRows = 1024
const backlogMaxLineBytes = 64 << 20

// StageVerifiedBacklogSourceWindow durably stages validated FI source envelopes
// into the private recovery schema. A source-window marker commits atomically
// with ALL of its source rows. Replays verify persisted row identities.
//
// This is NOT complete typed relational ingestion, not an Accepted journal
// event, and not authority to publish a generation. Only the isolated test
// fixture currently installs the private fi_recovery schema.
func StageVerifiedBacklogSourceWindow(
	ctx context.Context, conn *pgx.Conn, g *PreparedGeneration,
	limits BacklogWindowLimits, index int, privateRoot string,
) error {
	if ctx == nil || conn == nil {
		return errors.New("FI backlog source stage: context and connection required")
	}
	if err := ctx.Err(); err != nil { return err }
	descriptors, err := DescribeBacklogWindows(g,limits)
	if err != nil { return err }
	if index < 0 || index >= len(descriptors) { return errors.New("FI backlog source stage: invalid window index") }
	d := descriptors[index]
	if d.EndRecord > math.MaxInt64 || d.DataBytes > math.MaxInt64 {
		return errors.New("FI backlog source stage: source totals exceed PostgreSQL bigint")
	}
	// Never trust a persisted artifact checkpoint without checking the bytes.
	if err := VerifyMaterializedBacklogWindow(ctx,g,limits,index,privateRoot);err!=nil {
		return fmt.Errorf("FI backlog source stage: source copy verification failed: %w",err)
	}
	var dbUser,dbName string
	if err:=conn.QueryRow(ctx,"SELECT current_user,current_database()").Scan(&dbUser,&dbName);err!=nil{return err}
	if dbUser!="fi_ingest"||dbName!="fi" {return fmt.Errorf("FI backlog source stage: unexpected database identity %s/%s",dbUser,dbName)}
	receipt,err:=hex.DecodeString(d.ReceiptSHA256);if err!=nil{return err}
	descriptorDigest,err:=hex.DecodeString(d.DigestSHA256);if err!=nil{return err}
	previousDigest,err:=hex.DecodeString(d.PreviousDigestSHA256);if err!=nil{return err}
	tx,err:=conn.Begin(ctx);if err!=nil{return err}
	defer tx.Rollback(context.Background())
	// Serialize all windows under the original signed receipt identity.
	var lockKey int64
	for _,b:=range receipt[:8] {lockKey=(lockKey<<8)|int64(b)}
	if _,err:=tx.Exec(ctx,"SELECT pg_advisory_xact_lock($1::bigint)",lockKey);err!=nil{return err}
	var accepted bool
	if err:=tx.QueryRow(ctx,`SELECT EXISTS(SELECT 1 FROM fi.recorded_generation WHERE source_id=$1 AND generation_id=$2)`,
		d.SourceID,d.GenerationID).Scan(&accepted);err!=nil{return err}
	if accepted {return errors.New("FI backlog source stage: original generation already authoritative")}
	var artifactHash []byte
	if err:=tx.QueryRow(ctx,`
SELECT descriptor_sha256
FROM fi_recovery.verified_artifact_window
WHERE receipt_sha256=$1 AND window_index=$2
AND source_id=$3 AND generation_id=$4
`,receipt,index,d.SourceID,d.GenerationID).Scan(&artifactHash);err!=nil {
		return fmt.Errorf("FI backlog source stage: verified-artifact checkpoint missing or invalid: %w",err)
	}
	if subtle.ConstantTimeCompare(artifactHash,descriptorDigest)!=1 {
		return errors.New("FI backlog source stage: artifact checkpoint does not match current signed window")
	}
	var existingDigest,existingDescriptor,existingPrevious []byte
	var existingRecords,existingBytes,existingStartRecord,existingEndRecord int64
	var existingStartBatch,existingEndBatch int
	err=tx.QueryRow(ctx,`
SELECT rows_digest_sha256,descriptor_sha256,previous_digest_sha256,
       staged_records,staged_bytes,start_batch,end_batch,start_record,end_record
FROM fi_recovery.source_window WHERE receipt_sha256=$1 AND window_index=$2
`,receipt,index).Scan(&existingDigest,&existingDescriptor,&existingPrevious,
		&existingRecords,&existingBytes,&existingStartBatch,&existingEndBatch,
		&existingStartRecord,&existingEndRecord)
	if err==nil {
		if subtle.ConstantTimeCompare(existingDescriptor,descriptorDigest)!=1 ||
			subtle.ConstantTimeCompare(existingPrevious,previousDigest)!=1 ||
			existingRecords!=int64(d.EndRecord-d.StartRecord) || existingBytes!=int64(d.DataBytes) ||
			existingStartBatch!=d.StartBatch || existingEndBatch!=d.EndBatch ||
			existingStartRecord!=int64(d.StartRecord) || existingEndRecord!=int64(d.EndRecord) {
			return errors.New("FI backlog source stage: conflicting existing source-window marker")
		}
		// Recompute source digest AND database rows. The completed marker itself
		// is never proof of the persisted rows' integrity or completeness.
		sourceHash,records,bytes,err:=scanBacklogWindowRecords(ctx,g,d,index,privateRoot,nil)
		if err!=nil{return err}
		if records!=d.EndRecord-d.StartRecord||bytes!=d.DataBytes ||
			subtle.ConstantTimeCompare(sourceHash,existingDigest)!=1 {
			return errors.New("FI backlog source stage: resumed source rows differ from committed marker")
		}
		dbHash,dbRecords,dbBytes,err:=hashBacklogDatabaseSourceRows(ctx,tx,receipt,index)
		if err!=nil{return err}
		if dbRecords!=records||dbBytes!=bytes||subtle.ConstantTimeCompare(dbHash,sourceHash)!=1 {
			return errors.New("FI backlog source stage: persisted source rows do not match original custody")
		}
		return tx.Commit(ctx)
	}
	if !errors.Is(err,pgx.ErrNoRows){return err}

	var priorIndex,priorEndBatch int
	var priorEndRecord int64
	var priorDescriptor []byte
	err=tx.QueryRow(ctx,`
SELECT window_index,end_batch,end_record,descriptor_sha256
FROM fi_recovery.source_window WHERE receipt_sha256=$1
ORDER BY window_index DESC LIMIT 1
`,receipt).Scan(&priorIndex,&priorEndBatch,&priorEndRecord,&priorDescriptor)
	if errors.Is(err,pgx.ErrNoRows) {
		if index!=0 || d.StartBatch!=0 || d.StartRecord!=0 {
			return errors.New("FI backlog source stage: first source window must begin at zero")
		}
	} else if err!=nil {return err} else if priorIndex+1!=index ||
		priorEndBatch!=d.StartBatch || priorEndRecord!=int64(d.StartRecord) ||
		subtle.ConstantTimeCompare(priorDescriptor,previousDigest)!=1 {
		return errors.New("FI backlog source stage: prior committed source window is missing or discontinuous")
	}

	copyCols:=[]string{"receipt_sha256","window_index","batch_index","record_ordinal",
		"version","record_kind","scope_id","written_at","written_at_original","record_bytes","record_sha256"}
	rows:=make([][]any,0,backlogSourceCopyRows)
	flush:=func()error{
		if len(rows)==0{return nil}
		n,err:=tx.CopyFrom(ctx,pgx.Identifier{"fi_recovery","pending_source_record"},copyCols,pgx.CopyFromRows(rows))
		if err!=nil{return err}
		if n!=int64(len(rows)){return errors.New("FI backlog source stage: incomplete COPY")}
		rows=rows[:0]
		return nil
	}
	sourceHash,records,bytes,err:=scanBacklogWindowRecords(ctx,g,d,index,privateRoot,
		func(batchIndex int, ordinal int64, item SourceRecord)error{
			digest,err:=hex.DecodeString(item.RecordSHA256)
			if err!=nil{return err}
			rows=append(rows,[]any{receipt,index,batchIndex,ordinal,
				item.Record.Version,item.Record.RecordKind,item.Record.ScopeID,item.WrittenAtUTC,
				item.Record.WrittenAt,item.RecordBytes,digest})
			if len(rows)>=backlogSourceCopyRows{return flush()}
			return nil
		})
	if err!=nil{return err}
	if err:=flush();err!=nil{return fmt.Errorf("FI backlog source stage: source COPY: %w",err)}
	if records!=d.EndRecord-d.StartRecord || bytes!=d.DataBytes {
		return errors.New("FI backlog source stage: source total mismatch against signed receipt")
	}
	// Check the rows inside this same transaction BEFORE committing the marker.
	dbHash,dbRecords,dbBytes,err:=hashBacklogDatabaseSourceRows(ctx,tx,receipt,index)
	if err!=nil{return err}
	if dbRecords!=records || dbBytes!=bytes || subtle.ConstantTimeCompare(dbHash,sourceHash)!=1 {
		return errors.New("FI backlog source stage: staged SQL rows differ from validated source")
	}
	_,err=tx.Exec(ctx,`
INSERT INTO fi_recovery.source_window (
 receipt_sha256,window_index,descriptor_sha256,previous_digest_sha256,
 start_batch,end_batch,start_record,end_record,staged_records,staged_bytes,rows_digest_sha256
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
`,receipt,index,descriptorDigest,previousDigest,d.StartBatch,d.EndBatch,
		int64(d.StartRecord),int64(d.EndRecord),int64(records),int64(bytes),sourceHash)
	if err!=nil{return fmt.Errorf("FI backlog source stage: write completed marker: %w",err)}
	return tx.Commit(ctx)
}

func scanBacklogWindowRecords(
	ctx context.Context, g *PreparedGeneration, d BacklogCheckpointDescriptor,
	index int, root string,
	consume func(batchIndex int, ordinal int64, item SourceRecord) error,
) ([]byte, uint64, uint64, error) {
	dir := filepath.Join(root, "receipt-"+d.ReceiptSHA256, fmt.Sprintf("window-%08d", index))
	if err := verifyPrivateBacklogRoot(dir); err != nil { return nil,0,0,err }
	if d.StartBatch < 0 || d.EndBatch > len(g.Batches) || d.StartBatch >= d.EndBatch {
		return nil,0,0,errors.New("FI backlog source stage: invalid batch range")
	}
	h := sha256.New()
	var totalRecords,totalBytes uint64
	for batchIndex:=d.StartBatch;batchIndex<d.EndBatch;batchIndex++{
		if err:=ctx.Err();err!=nil{return nil,0,0,err}
		batch:=g.Batches[batchIndex]
		path:=filepath.Join(dir,fmt.Sprintf("batch-%08d.data",batchIndex))
		info,err:=os.Lstat(path)
		if err!=nil{return nil,0,0,err}
		if info.Mode()&os.ModeSymlink!=0||!info.Mode().IsRegular()||
			info.Mode().Perm()!=0600||info.Size()!=batch.Manifest.DataBytes {
			return nil,0,0,fmt.Errorf("FI backlog source stage: data path metadata mismatch for batch %d",batchIndex)
		}
		file,err:=os.Open(path)
		if err!=nil{return nil,0,0,err}
		reader:=bufio.NewReaderSize(file,64<<10)
		batchHash:=sha256.New()
		var count,byteCount int64
		var streamErr error
		for {
			if err:=ctx.Err();err!=nil{streamErr=err;break}
			raw,err:=readBacklogSourceJSONL(reader)
			if errors.Is(err,io.EOF){break}
			if err!=nil{streamErr=err;break}
			count++
			byteCount+=int64(len(raw))
			_,_=batchHash.Write(raw)
			item,err:=PrepareSourceRecord(raw)
			if err!=nil{streamErr=fmt.Errorf("FI backlog source stage: batch %d record %d: %w",batchIndex,count,err);break}
			digest,err:=hex.DecodeString(item.RecordSHA256)
			if err!=nil{streamErr=err;break}
			backlogHashSourceRow(h,batchIndex,count,item.Record.Version,item.Record.RecordKind,
				item.Record.ScopeID,item.Record.WrittenAt,item.RecordBytes,digest)
			if consume!=nil{
				if err:=consume(batchIndex,count,item);err!=nil{streamErr=err;break}
			}
		}
		closeErr:=file.Close()
		if streamErr!=nil{return nil,0,0,errors.Join(streamErr,closeErr)}
		if closeErr!=nil{return nil,0,0,closeErr}
		if count!=int64(batch.Manifest.RecordCount) ||
			byteCount!=batch.Manifest.DataBytes ||
			hex.EncodeToString(batchHash.Sum(nil))!=batch.Manifest.DataSHA256 {
			return nil,0,0,fmt.Errorf("FI backlog source stage: staged batch %d violates signed manifest count/bytes/SHA",batchIndex)
		}
		totalRecords+=uint64(count)
		totalBytes+=uint64(byteCount)
	}
	return h.Sum(nil),totalRecords,totalBytes,nil
}

// hashBacklogDatabaseSourceRows calculates the same canonical digest as the
// staged JSONL scanner; it is used both before commit and for restart proof.
func hashBacklogDatabaseSourceRows(ctx context.Context,tx pgx.Tx,receipt []byte,index int)([]byte,uint64,uint64,error){
	rows,err:=tx.Query(ctx,`
SELECT batch_index,record_ordinal,version,record_kind,scope_id,written_at_original,record_bytes,record_sha256
FROM fi_recovery.pending_source_record
WHERE receipt_sha256=$1 AND window_index=$2
ORDER BY batch_index,record_ordinal
`,receipt,index)
	if err!=nil{return nil,0,0,err}
	defer rows.Close()
	h:=sha256.New()
	var n,bytes uint64
	for rows.Next(){
		var batchIndex,recordBytes int
		var ordinal int64
		var version,kind,scope string
		var written string
		var digest []byte
		if err:=rows.Scan(&batchIndex,&ordinal,&version,&kind,&scope,&written,&recordBytes,&digest);err!=nil{return nil,0,0,err}
		backlogHashSourceRow(h,batchIndex,ordinal,version,kind,scope,written,recordBytes,digest)
		n++;bytes+=uint64(recordBytes)
	}
	if err:=rows.Err();err!=nil{return nil,0,0,err}
	return h.Sum(nil),n,bytes,nil
}
func backlogHashSourceRow(h hash.Hash,batchIndex int,ordinal int64,version,kind,scope,written string,bytes int,digest []byte){
	backlogDigestNumber(h,uint64(batchIndex))
	backlogDigestNumber(h,uint64(ordinal))
	backlogDigestString(h,version)
	backlogDigestString(h,kind)
	backlogDigestString(h,scope)
	backlogDigestString(h,written)
	backlogDigestNumber(h,uint64(bytes))
	_,_=h.Write(digest)
}

// readBacklogSourceJSONL is bounded even when presented with malformed input.
func readBacklogSourceJSONL(r *bufio.Reader)([]byte,error){
	buf:=make([]byte,0,4096)
	for {
		part,err:=r.ReadSlice('\n')
		if len(part)>backlogMaxLineBytes-len(buf){
			return nil,errors.New("FI backlog source stage: record exceeds memory limit")
		}
		buf=append(buf,part...)
		if err==nil{return buf,nil}
		if errors.Is(err,bufio.ErrBufferFull){continue}
		if errors.Is(err,io.EOF)&&len(buf)==0{return nil,io.EOF}
		if errors.Is(err,io.EOF){return nil,errors.New("FI backlog source stage: missing final LF")}
		return nil,err
	}
}
