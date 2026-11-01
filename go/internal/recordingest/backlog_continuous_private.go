// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
 "bytes"
 "context"
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "strings"
 "time"

 "github.com/Iron-Signal-Systems/fi/go/internal/generationrecorder"
 "github.com/Iron-Signal-Systems/fi/go/internal/spool"
 "github.com/Iron-Signal-Systems/fi/go/internal/transportgeneration"
 "github.com/jackc/pgx/v5"
)

// BacklogContinuousProgress describes observed PRIVATE recovery progress.
// Committed counts are per-window database checkpoints, not Accepted ingest.
type BacklogContinuousProgress struct {
 BatchesSeen int
 TotalBatches int
 RecordsInspected uint64
 WindowCommitted int // -1 for a scan-only progress event
 TotalWindows int
 RecordsDurable uint64
 WindowDuration time.Duration
 Elapsed time.Duration
}

// RecoverBacklogContinuousPrivate performs a SINGLE full custody decode
// while committing each new bounded window to the existing PRIVATE schemas.
// It does not write any authoritative fi.* records or Accepted journal rows.
//
// The previously authenticated 8399-batch metadata in the shadow DB provides
// the complete, deterministic window plan before streaming begins. Every
// encountered data+manifest artifact must match that exact indexed identity.
// DB writes are provisional until the full FIGT stream, current signing trust,
// full transfer SHA and receipt identity have all been revalidated.
//
// The run resumes after a contiguous, previously committed prefix. It never
// silently skips an uncommitted window. A crash leaves previously committed
// private windows intact and no Accepted generation.
func RecoverBacklogContinuousPrivate(
 ctx context.Context,
 reader, writer *pgx.Conn,
 config GenerationLoadConfig,
 generationID string,
 limits BacklogWindowLimits,
 privateRoot string,
 startWindow int,
 report func(BacklogContinuousProgress),
) (BacklogGenerationVerification,error) {
 var empty BacklogGenerationVerification
 if ctx==nil||reader==nil||writer==nil||reader==writer{
  return empty,errors.New("FI continuous private: distinct reader and writer connections required")
 }
 if err:=ctx.Err();err!=nil{return empty,err}
 if err:=validateGenerationLoadConfig(config,generationID);err!=nil{return empty,err}
 if startWindow<1{return empty,errors.New("FI continuous private: requires an existing committed prefix")}
 if limits.MaxRecords==0||limits.MaxDataBytes==0||limits.MaxDataBytes>256<<20{
  return empty,errors.New("FI continuous private: bounded window limits required")
 }
 if err:=verifyPrivateBacklogRoot(privateRoot);err!=nil{return empty,err}
 var user,db string
 if err:=writer.QueryRow(ctx,"SELECT current_user,current_database()").Scan(&user,&db);err!=nil{return empty,err}
 if user!="fi_ingest"||db!="fi"{return empty,errors.New("FI continuous private: unexpected SQL identity")}

 // Start from the SAME immutable recorded receipt and authenticated private
 // batch metadata that the first twelve completed windows used.
 root:=config.RecordedRoot
 if config.SourceNamespaces {
  var err error
  root,err=generationrecorder.RecordedSourceDirectory(root,config.SourceID)
  if err!=nil{return empty,err}
 }
 raw,err:=readImmutableReceipt(filepath.Join(root,
  generationrecorder.RecordedReceiptObjectName(config.SourceID,generationID)))
 if err!=nil{return empty,err}
 receipt,err:=generationrecorder.UnmarshalRecordedReceipt(raw)
 if err!=nil{return empty,err}
 if receipt.Descriptor.SourceID!=config.SourceID||receipt.Descriptor.GenerationID!=generationID{
  return empty,errors.New("FI continuous private: receipt identity mismatch")
 }
 digest:=sha256.Sum256(raw)
 receiptSHA:=hex.EncodeToString(digest[:])
 receiptBytes:=digest[:]
 transferBytes,err:=hex.DecodeString(receipt.TransferSHA256);if err!=nil{return empty,err}

 rows,err:=writer.Query(ctx,`
SELECT sb.manifest_artifact_name,sb.data_artifact_name,sb.manifest_version,
 sb.batch_id,sb.target_batch_size,sb.record_count,sb.data_bytes,
 sb.data_sha256,sb.data_file,sb.collector_executable_path,
 sb.collector_executable_sha256,sb.created_at,sb.completed_at,
 sb.manifest_bytes,sb.manifest_sha256
FROM fi_recovery_projection.source_batch sb
JOIN fi_recovery_projection.recorded_generation g
 ON g.recorded_generation_id=sb.recorded_generation_id
WHERE g.source_id=$1 AND g.generation_id=$2
 AND g.receipt_sha256=$3 AND g.transfer_sha256=$4
ORDER BY sb.batch_id
`,config.SourceID,generationID,receiptBytes,transferBytes)
 if err!=nil{return empty,err}
 batches:=make([]PreparedBatch,0,int(receipt.BatchCount))
 for rows.Next(){
  var manifestName,dataName,version,batchID,dataFile,executable string
  var target,count int
  var dataSize,manifestSize int64
  var dataHash,executableHash,manifestHash []byte
  var created,completed time.Time
  err=rows.Scan(&manifestName,&dataName,&version,&batchID,&target,&count,
   &dataSize,&dataHash,&dataFile,&executable,&executableHash,
   &created,&completed,&manifestSize,&manifestHash)
  if err!=nil{rows.Close();return empty,err}
  if len(dataHash)!=32||len(executableHash)!=32||len(manifestHash)!=32||
   manifestSize<=0||manifestSize>int64(config.MaxManifestBytes){
   rows.Close();return empty,errors.New("FI continuous private: malformed indexed manifest")
  }
  batches=append(batches,PreparedBatch{
   BatchID:batchID,DataArtifactName:dataName,ManifestArtifactName:manifestName,
   ManifestBytes:int(manifestSize),ManifestSHA256:hex.EncodeToString(manifestHash),
   Manifest:spool.Manifest{
    Version:version,BatchID:batchID,TargetBatchSize:target,
    RecordCount:count,DataBytes:dataSize,DataSHA256:hex.EncodeToString(dataHash),
    DataFile:dataFile,Collector:spool.CollectorIdentity{
     ExecutablePath:executable,ExecutableSHA256:hex.EncodeToString(executableHash),
    },
    CreatedAt:created.UTC().Format(time.RFC3339Nano),
    CompletedAt:completed.UTC().Format(time.RFC3339Nano),
   },
  })
  if uint64(len(batches))>receipt.BatchCount{
   rows.Close();return empty,errors.New("FI continuous private: too many indexed batches")
  }
 }
 err=rows.Err()
 rows.Close()
 if err!=nil{return empty,err}
 if uint64(len(batches))!=receipt.BatchCount{
  return empty,fmt.Errorf("FI continuous private: incomplete source-batch index %d/%d",len(batches),receipt.BatchCount)
 }
 g:=&PreparedGeneration{Batches:batches,Receipt:receipt,ReceiptBytes:len(raw),
  ReceiptRawBytes:append([]byte(nil),raw...),ReceiptSHA256:receiptSHA}
 descriptors,err:=DescribeBacklogWindows(g,limits)
 if err!=nil{return empty,err}
 if startWindow>=len(descriptors){return empty,errors.New("FI continuous private: start window outside original generation")}

 // Validate all pre-existing checkpoint indices against the signed window
 // chain (artifact, source and typed markers), not merely a last marker.
 prior,err:=writer.Query(ctx,`
SELECT a.window_index,a.descriptor_sha256,s.descriptor_sha256,t.descriptor_sha256
FROM fi_recovery.verified_artifact_window a
JOIN fi_recovery.source_window s
 ON s.receipt_sha256=a.receipt_sha256 AND s.window_index=a.window_index
JOIN fi_recovery.typed_window t
 ON t.receipt_sha256=a.receipt_sha256 AND t.window_index=a.window_index
WHERE a.receipt_sha256=$1 AND a.window_index < $2
ORDER BY a.window_index
`,receiptBytes,startWindow)
 if err!=nil{return empty,err}
 n:=0
 for prior.Next(){
  var idx int
  var a,b,c []byte
  if err:=prior.Scan(&idx,&a,&b,&c);err!=nil{prior.Close();return empty,err}
  if idx!=n||n>=startWindow{
   prior.Close();return empty,errors.New("FI continuous private: missing/disordered prior window")
  }
  want,err:=hex.DecodeString(descriptors[n].DigestSHA256)
  if err!=nil{prior.Close();return empty,err}
  if !bytes.Equal(a,want)||!bytes.Equal(b,want)||!bytes.Equal(c,want){
   prior.Close();return empty,fmt.Errorf("FI continuous private: prior window %d hash mismatch",n)
  }
  n++
 }
 err=prior.Err()
 prior.Close()
 if err!=nil{return empty,err}
 if n!=startWindow{return empty,fmt.Errorf("FI continuous private: only %d of %d prior completed checkpoints",n,startWindow)}
 var authoritative bool
 if err:=writer.QueryRow(ctx,`
SELECT EXISTS(SELECT 1 FROM fi.recorded_generation
 WHERE source_id=$1 AND generation_id=$2)`,config.SourceID,generationID).Scan(&authoritative);err!=nil{return empty,err}
 if authoritative{return empty,errors.New("FI continuous private: generation already authoritative")}

 trust,err:=loadInstalledGenerationTrust(config.SourceID)
 if err!=nil{return empty,err}
 if !strings.EqualFold(trust.Source.SourceID,config.SourceID)||
  trust.Root==nil||trust.BatchIssuer==nil||trust.BatchCRL==nil{
  return empty,errors.New("FI continuous private: enrolled signing trust incomplete")
 }
 custodyPath:=filepath.Join(config.CustodyRoot,
  transportgeneration.DurableCustodyObjectName(config.SourceID,generationID))
 info,err:=os.Lstat(custodyPath)
 if err!=nil{return empty,err}
 if !info.Mode().IsRegular()||info.Mode().Perm()!=0400||info.Size()<=0{
  return empty,errors.New("FI continuous private: immutable custody metadata invalid")
 }
 stageDir,err:=os.MkdirTemp("","fi-backlog-continuous-*")
 if err!=nil{return empty,err}
 lease,err:=newGenerationStageLease(stageDir)
 if err!=nil{_ = os.RemoveAll(stageDir);return empty,err}
 g.stagedDirectory=stageDir
 g.stageLease=lease
 defer g.Close()

 started:=time.Now()
 nextBatch:=0
 windowIndex:=startWindow
 var pending bool
 var inspected spool.DataInspection
 var scannedRecords uint64
 var durableRecords=descriptors[startWindow-1].EndRecord
 windowStarted:=time.Now()
 factory:=func(desc transportgeneration.Descriptor)(transportgeneration.CanonicalArtifactHandler,error){
  if desc!=receipt.Descriptor{return nil,errors.New("FI continuous private: transport descriptor changed")}
  return func(name string,r io.Reader)error{
   if err:=ctx.Err();err!=nil{return err}
   if nextBatch>=len(g.Batches){return errors.New("FI continuous private: excess source artifacts")}
   batch:=&g.Batches[nextBatch]
   if !pending {
    if name!=batch.DataArtifactName{
     return fmt.Errorf("FI continuous private: data artifact name mismatch at batch %d",nextBatch)
    }
    shouldRetain:=nextBatch>=descriptors[windowIndex].StartBatch
    if shouldRetain{
     path:=filepath.Join(stageDir,fmt.Sprintf("batch-%08d.data",nextBatch))
     f,err:=os.OpenFile(path,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600)
     if err!=nil{return err}
     inspected,err=spool.InspectData(io.TeeReader(
      io.LimitReader(r,int64(limits.MaxDataBytes)+1),f))
     err=errors.Join(err,f.Close())
     if err!=nil{return err}
     batch.DataPath=path
    }else {
     var err error
     inspected,err=spool.InspectData(io.LimitReader(r,int64(limits.MaxDataBytes)+1))
     if err!=nil{return err}
    }
    if inspected.DataBytes!=batch.Manifest.DataBytes||
     inspected.RecordCount!=batch.Manifest.RecordCount||
     inspected.DataSHA256!=batch.Manifest.DataSHA256{
     return fmt.Errorf("FI continuous private: batch %d does not match previously authenticated source index",nextBatch)
    }
    pending=true
    return nil
   }
   if name!=batch.ManifestArtifactName{
    return fmt.Errorf("FI continuous private: manifest artifact name mismatch at batch %d",nextBatch)
   }
   original,err:=io.ReadAll(io.LimitReader(r,int64(config.MaxManifestBytes)+1))
   if err!=nil{return err}
   if len(original)!=batch.ManifestBytes{return fmt.Errorf("FI continuous private: manifest length changed at batch %d",nextBatch)}
   h:=sha256.Sum256(original)
   if hex.EncodeToString(h[:])!=batch.ManifestSHA256{
    return fmt.Errorf("FI continuous private: manifest hash mismatch at batch %d",nextBatch)
   }
   m,err:=spool.DecodeManifest(bytes.NewReader(original))
   if err!=nil{return err}
   if err:=spool.VerifyManifestData(m,inspected);err!=nil{return err}
   if m.BatchID!=batch.BatchID||m.DataFile!=batch.DataArtifactName||
    m.DataSHA256!=batch.Manifest.DataSHA256||
    m.DataBytes!=batch.Manifest.DataBytes||
    m.RecordCount!=batch.Manifest.RecordCount||
    m.TargetBatchSize!=batch.Manifest.TargetBatchSize||
    m.Version!=batch.Manifest.Version{
    return fmt.Errorf("FI continuous private: manifest content changed at batch %d",nextBatch)
   }
   if nextBatch>=descriptors[windowIndex].StartBatch{
    batch.ManifestRawBytes=original
   }
   scannedRecords+=uint64(m.RecordCount)
   nextBatch++
   pending=false
   if nextBatch==descriptors[windowIndex].EndBatch{
    index:=windowIndex
    start:=time.Now()
    if _,err:=MaterializeBacklogWindow(ctx,g,limits,index,privateRoot);err!=nil{
     return fmt.Errorf("FI continuous private: window %d durable materialization: %w",index,err)
    }
    if err:=RecordVerifiedBacklogArtifactWindow(ctx,writer,g,limits,index,privateRoot);err!=nil{
     return fmt.Errorf("FI continuous private: window %d artifact checkpoint: %w",index,err)
    }
    if err:=StageVerifiedBacklogSourceWindow(ctx,writer,g,limits,index,privateRoot);err!=nil{
     return fmt.Errorf("FI continuous private: window %d source stage: %w",index,err)
    }
    if err:=StageBacklogTypedWindow(ctx,reader,writer,g,limits,index,privateRoot);err!=nil{
     return fmt.Errorf("FI continuous private: window %d typed stage: %w",index,err)
    }
    // Data has been durably materialized and every private marker committed.
    // Release the disposable per-window staging files immediately.
    for i:=descriptors[index].StartBatch;i<descriptors[index].EndBatch;i++{
     if g.Batches[i].DataPath==""{return errors.New("FI continuous private: staged batch missing before cleanup")}
     if err:=os.Remove(g.Batches[i].DataPath);err!=nil{return err}
     g.Batches[i].DataPath=""
     g.Batches[i].ManifestRawBytes=nil
    }
    durableRecords=descriptors[index].EndRecord
    if report!=nil{report(BacklogContinuousProgress{
     BatchesSeen:nextBatch,TotalBatches:len(g.Batches),
     RecordsInspected:scannedRecords,WindowCommitted:index,
     TotalWindows:len(descriptors),RecordsDurable:durableRecords,
     WindowDuration:time.Since(start),Elapsed:time.Since(started),
    })}
    windowIndex++
    windowStarted=time.Now()
   }else if report!=nil&&nextBatch%128==0{
    report(BacklogContinuousProgress{
     BatchesSeen:nextBatch,TotalBatches:len(g.Batches),
     RecordsInspected:scannedRecords,WindowCommitted:-1,
     TotalWindows:len(descriptors),RecordsDurable:durableRecords,
     WindowDuration:time.Since(windowStarted),Elapsed:time.Since(started),
    })
   }
   return nil
  },nil
 }

 result,err:=transportgeneration.ReadDiscoveredDurableCustodyArtifacts(
  transportgeneration.DiscoveredCustody{Path:custodyPath,Bytes:uint64(info.Size())},
  transportgeneration.CustodyConfig{RootDir:config.CustodyRoot,
   Receive:transportgeneration.ReceiveConfig{
    BatchCRL:trust.BatchCRL,BatchIssuer:trust.BatchIssuer,CurrentTime:time.Now(),
    MaxCanonicalBytes:config.MaxCanonicalBytes,MaxEncodedBytes:config.MaxEncodedBytes,
    Root:trust.Root,Source:trust.Source,
   },
  },factory)
 if err!=nil{return empty,fmt.Errorf("FI continuous private: complete signed transfer not validated: %w",err)}
 if result.Transfer.Descriptor!=receipt.Descriptor ||
  result.Transfer.MetadataSHA256!=receipt.MetadataSHA256 ||
  result.Transfer.MetadataBytes!=receipt.MetadataBytes ||
  result.Transfer.TransferSHA256!=receipt.TransferSHA256 ||
  result.Transfer.TransferBytes!=receipt.TransferBytes{
  return empty,errors.New("FI continuous private: complete signed transfer identity differs from recorded receipt")
 }
 if pending||nextBatch!=len(g.Batches)||windowIndex!=len(descriptors)||
  scannedRecords!=receipt.RecordCount||durableRecords!=receipt.RecordCount{
  return empty,fmt.Errorf("FI continuous private: incomplete transfer/checkpoints batches=%d/%d windows=%d/%d records=%d/%d durable=%d",
   nextBatch,len(g.Batches),windowIndex,len(descriptors),scannedRecords,receipt.RecordCount,durableRecords)
 }
 // ONLY NOW has the complete original signed FIGT been revalidated. Still
 // no Accepted journal: this returns an independently checked PRIVATE report.
 verified,err:=VerifyCompleteBacklogTypedGeneration(ctx,reader,g,limits)
 if err!=nil{return empty,fmt.Errorf("FI continuous private: full private projection verification: %w",err)}
 return verified,nil
}
