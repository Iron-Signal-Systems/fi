// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
 "bytes"
 "context"
 "errors"
 "fmt"
 "time"

 "github.com/Iron-Signal-Systems/fi/go/internal/spool"
 "github.com/jackc/pgx/v5"
)

// Cache consumption intentionally does NOT read the signed FIGT object.
// The entire transfer was already verified by the seed loader before
// publication of the receipt-bound immutable cache directory. Each
// window still rechecks every signed manifest SHA and every source data SHA
// while creating the original durable source/typed checkpoint. The source
// files in the cache are never removed or modified by these trials.
func recoverBacklogVerifiedCachedWindows(
 ctx context.Context,reader,writer *pgx.Conn,g *PreparedGeneration,
 limits BacklogWindowLimits,privateRoot string,startWindow int,
 cacheRoot string,descriptors []BacklogWindowDescriptor,
 report func(BacklogContinuousProgress),
)(BacklogGenerationVerification,error){
 var empty BacklogGenerationVerification
 if g==nil||g.ReceiptSHA256==""||startWindow<1||startWindow>=len(descriptors){
  return empty,errors.New("FI cached recovery: incomplete generation or invalid checkpoint prefix")
 }
 cacheDir,err:=backlogVerifiedCacheOpen(cacheRoot,g.ReceiptSHA256,
  g.Receipt.TransferSHA256,g.Receipt.BatchCount,g.Receipt.RecordCount,g.Receipt.DataBytes)
 if err!=nil{return empty,fmt.Errorf("FI cached recovery: verified cache marker: %w",err)}
 started:=time.Now()
 durable:=descriptors[startWindow-1].EndRecord
 var consumedRecords uint64
 for window:=startWindow;window<len(descriptors);window++{
  if err=ctx.Err();err!=nil{return empty,err}
  d:=descriptors[window]
  if d.StartBatch<0||d.EndBatch>len(g.Batches)||d.StartBatch>=d.EndBatch{
   return empty,fmt.Errorf("FI cached recovery: invalid signed batch range at window %d",window)
  }
  windowStart:=time.Now()
  for i:=d.StartBatch;i<d.EndBatch;i++{
   if err=ctx.Err();err!=nil{return empty,err}
   b:=&g.Batches[i]
   raw,readErr:=backlogVerifiedCacheManifest(cacheDir,i,b.ManifestSHA256,1<<20)
   if readErr!=nil{return empty,fmt.Errorf("FI cached recovery: batch %d manifest: %w",i,readErr)}
   manifest,decodeErr:=spool.DecodeManifest(bytes.NewReader(raw))
   if decodeErr!=nil{return empty,fmt.Errorf("FI cached recovery: batch %d decode: %w",i,decodeErr)}
   if manifest.BatchID!=b.BatchID || manifest.DataFile!=b.DataArtifactName ||
    manifest.Version!=b.Manifest.Version || manifest.DataSHA256!=b.Manifest.DataSHA256 ||
    manifest.DataBytes!=b.Manifest.DataBytes ||
    manifest.RecordCount!=b.Manifest.RecordCount ||
    manifest.TargetBatchSize!=b.Manifest.TargetBatchSize{
    return empty,fmt.Errorf("FI cached recovery: batch %d differs from authenticated source index",i)
   }
   b.ManifestRawBytes=raw
   b.DataPath=backlogCacheBatchData(cacheDir,i)
  }
  tick:=time.Now()
  if _,err=MaterializeBacklogWindow(ctx,g,limits,window,privateRoot);err!=nil{
   return empty,fmt.Errorf("FI cached recovery: window %d verified artifact: %w",window,err)
  }
  artifactDuration:=time.Since(tick)
  tick=time.Now()
  if err=RecordVerifiedBacklogArtifactWindow(ctx,writer,g,limits,window,privateRoot);err!=nil{
   return empty,fmt.Errorf("FI cached recovery: window %d artifact marker: %w",window,err)
  }
  ledgerDuration:=time.Since(tick)
  tick=time.Now()
  if err=StageBacklogSourceAndTypedWindow(ctx,reader,writer,g,limits,window,privateRoot);err!=nil{
   return empty,fmt.Errorf("FI cached recovery: window %d joined source+typed: %w",window,err)
  }
  typedDuration:=time.Since(tick)
  for i:=d.StartBatch;i<d.EndBatch;i++{
   // Never delete the shared verified cache; only release per-window handles.
   g.Batches[i].DataPath=""
   g.Batches[i].ManifestRawBytes=nil
  }
  durable=d.EndRecord
  consumedRecords+=d.EndRecord-d.StartRecord
  if report!=nil{
   report(BacklogContinuousProgress{
    BatchesSeen:d.EndBatch,TotalBatches:len(g.Batches),
    RecordsInspected:consumedRecords,WindowCommitted:window,
    WindowRecords:d.EndRecord-d.StartRecord,
    TotalWindows:len(descriptors),RecordsDurable:durable,
    WindowDuration:time.Since(windowStart),ArtifactDuration:artifactDuration,
    LedgerDuration:ledgerDuration,TypedDuration:typedDuration,
    Elapsed:time.Since(started),
   })
  }
 }
 if durable!=g.Receipt.RecordCount{
  return empty,errors.New("FI cached recovery: incomplete original recorded generation")
 }
 verified,err:=VerifyCompleteBacklogTypedGeneration(ctx,reader,g,limits)
 if err!=nil{return empty,fmt.Errorf("FI cached recovery: final private typed verification: %w",err)}
 return verified,nil
}
