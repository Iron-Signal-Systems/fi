//go:build freebsd

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package main

import (
 "context"
 "errors"
 "flag"
 "fmt"
 "os"
 "path/filepath"
 "strings"
 "time"

 "github.com/Iron-Signal-Systems/fi/go/internal/recordingest"
 "github.com/jackc/pgx/v5"
)

// Initially constrained to the one known pending signed generation. This
// CLI cannot accept a different source or write an Accepted journal event.
const sourceID = "iss-fs-22a.iss.local"
const generationID = "20261030T000032.061323100Z-3e38b2210771462c"
const expectedRecords uint64 = 15140785
const expectedBatches uint64 = 8399

func run() error {
 var source, generation, pg, custody, recorded, private string
 var namespaces, enable, streamLoader, indexedPrivate, preflightOnly, continuousPrivate bool
 var maxRuntime time.Duration
 var maxWindows, startWindow int
 var securityProfile string
 flag.StringVar(&source,"source","","exact original signed FI source")
 flag.StringVar(&generation,"generation-id","","exact original signed FI generation")
 flag.StringVar(&pg,"postgres","","FI ingest PostgreSQL connection string")
 flag.StringVar(&custody,"custody-root","/var/db/fi/custody/generation","original immutable FIGT custody")
 flag.StringVar(&recorded,"recorded-root","/var/db/fi/custody/recorded","original immutable recorded receipts")
 flag.StringVar(&private,"private-root","","pre-created private 0700 recovery directory")
 flag.BoolVar(&namespaces,"source-namespaces",false,"recorded receipt uses per-source directory")
 flag.BoolVar(&enable,"private-writes",false,"explicitly enable PRIVATE recovery writes")
 flag.BoolVar(&streamLoader,"stream-loader",false,"retain only requested window data while streaming and verifying entire signed custody")
 flag.BoolVar(&indexedPrivate,"indexed-private",false,"PRIVATE-ONLY resume from earlier complete validated shadow metadata; partial custody scan is NOT complete transfer verification")
 flag.BoolVar(&preflightOnly,"preflight-only",false,"read-only 10m indexed source preflight; no database writes or checkpoints")
 flag.BoolVar(&continuousPrivate,"continuous-private",false,"single signed custody stream, durable private commits for all remaining windows, full final verification; never Accepted")
 flag.DurationVar(&maxRuntime,"max-runtime",0,"hard run deadline including extraction and PostgreSQL operations, e.g. 10m")
 flag.StringVar(&securityProfile,"security-profile","P1","fixed bounded security source COPY batch: P1 conservative, P3 benchmark candidate; immutable for this invocation")
 flag.IntVar(&maxWindows,"max-windows",2,"private windows to process per invocation; 0 means to final window")
 flag.IntVar(&startWindow,"start-window",0,"original signed window index to resume from")
 flag.Parse()
 if flag.NArg()!=0 || source!=sourceID || generation!=generationID ||
  pg=="" || private=="" || (!enable&&!preflightOnly) || maxWindows<0 || maxWindows>1000 || startWindow<0 {
  return errors.New("exact source/generation, postgres, private-root, private-writes and max-windows 0..1000 required")
 }
 if !filepath.IsAbs(private)||!filepath.IsAbs(custody)||!filepath.IsAbs(recorded){
  return errors.New("all directories must be absolute")
 }
 for _,p:=range []string{private,custody,recorded}{
  info,err:=os.Lstat(p);if err!=nil{return fmt.Errorf("%s: %w",p,err)}
  if !info.IsDir() || info.Mode()&os.ModeSymlink!=0{
   return fmt.Errorf("directory is not real: %s",p)
  }
  if p==private && info.Mode().Perm()!=0700{
   return fmt.Errorf("private root %s must have exact 0700 permissions",p)
  }
 }
 if maxRuntime<0 || maxRuntime>10*time.Minute {return errors.New("max-runtime must be between 0 and 10m")}
 if preflightOnly && (!indexedPrivate||enable){return errors.New("preflight-only must use indexed-private WITHOUT private-writes")}
 if continuousPrivate && (indexedPrivate||streamLoader||preflightOnly||!enable||maxWindows!=0||startWindow<1){
  return errors.New("continuous-private requires private-writes, start-window>0, max-windows=0, no other recovery mode")
 }
 if indexedPrivate && (streamLoader||startWindow==0||maxWindows<1||maxWindows>2) {
  return errors.New("indexed-private requires start-window > 0 and one or two selected windows; cannot combine with stream-loader")
 }
 ctx:=context.Background()
 var stop context.CancelFunc
 if maxRuntime>0 {ctx,stop=context.WithTimeout(ctx,maxRuntime)} else {ctx,stop=context.WithCancel(ctx)}
 defer stop()
 if securityProfile!="P1" && securityProfile!="P3" {
  return errors.New("FI backlog recovery permits only benchmarked P1/P3 security profiles")
 }
 var profileErr error
 ctx,profileErr=recordingest.WithFixedSecurityBulkProfile(ctx,securityProfile)
 if profileErr!=nil{return profileErr}
 fmt.Printf("FI REAL BACKLOG CONFIG security_profile=%s max_window_records=32768 max_window_data_bytes=268435456\n",
  recordingest.FixedSecurityBulkProfileName(ctx))
 canonical, state,err:=recordingest.OpenPostgreSQL(ctx,pg)
 if err!=nil{return err}
 defer canonical.Close(context.Background())
 if state.RelationalTables!=49{return errors.New("FI relational schema is not 49 tables")}
 reader,err:=pgx.Connect(ctx,pg);if err!=nil{return err}
 defer reader.Close(context.Background())
 // Private schemas must already exist with the exact tested grants.
 var ready bool
 if err:=canonical.QueryRow(ctx,`
SELECT
 to_regclass('fi_recovery.verified_artifact_window') IS NOT NULL AND
 to_regclass('fi_recovery.pending_source_record') IS NOT NULL AND
 to_regclass('fi_recovery.source_window') IS NOT NULL AND
 to_regclass('fi_recovery.typed_window') IS NOT NULL AND
 to_regclass('fi_recovery_projection.recorded_generation') IS NOT NULL AND
 to_regclass('fi_recovery_projection.source_record') IS NOT NULL AND
 has_table_privilege(current_user,'fi_recovery.typed_window','SELECT') AND
 has_table_privilege(current_user,'fi_recovery.typed_window','INSERT') AND
 NOT has_table_privilege(current_user,'fi_recovery.typed_window','UPDATE,DELETE,TRUNCATE')
`).Scan(&ready);err!=nil{return fmt.Errorf("FI private schema verification: %w",err)}
 if !ready{return errors.New("FI private recovery schemas and append-only rights are not installed")}
 var already bool
 if err:=canonical.QueryRow(ctx,`
SELECT EXISTS(SELECT 1 FROM fi.recorded_generation
WHERE source_id=$1 AND generation_id=$2)
`,source,generation).Scan(&already);err!=nil{return err}
 if already{return errors.New("generation already authoritative; private recovery not required")}

 if indexedPrivate {
  fmt.Printf("FI REAL BACKLOG reading authenticated shadow batch index and selected custody prefix source=%s generation=%s; NOT full-transfer validation\n",source,generation)
 }else{
  fmt.Printf("FI REAL BACKLOG loading authenticated custody source=%s generation=%s\n",source,generation)
 }
 loadStarted:=time.Now()
 loadConfig:=recordingest.GenerationLoadConfig{
  CustodyRoot:custody,RecordedRoot:recorded,SourceID:source,SourceNamespaces:namespaces,
  MaxCanonicalBytes:68719476736,MaxEncodedBytes:68719476736,MaxManifestBytes:1048576,
 }
 limits:=recordingest.BacklogWindowLimits{MaxRecords:32768,MaxDataBytes:256<<20}
 if continuousPrivate {
  fmt.Printf("FI REAL BACKLOG CONTINUOUS PRIVATE start_window=%d original_signed_generation=%s\n",startWindow,generation)
  began:=time.Now()
  result,err:=recordingest.RecoverBacklogContinuousPrivate(ctx,reader,canonical,loadConfig,generation,limits,private,startWindow,
   func(p recordingest.BacklogContinuousProgress){
    if p.WindowCommitted>=0 {
     fmt.Printf("FI REAL BACKLOG DURABLE window=%d/%d inspected_batches=%d/%d records_through=%d/%d window=%s elapsed=%s\n",
      p.WindowCommitted+1,p.TotalWindows,p.BatchesSeen,p.TotalBatches,
      p.RecordsDurable,expectedRecords,p.WindowDuration.Round(time.Millisecond),p.Elapsed.Round(time.Millisecond))
    }else{
     fmt.Printf("FI REAL BACKLOG CONTINUOUS scanned_batches=%d/%d inspected_records=%d/%d durable_records=%d/%d elapsed=%s\n",
      p.BatchesSeen,p.TotalBatches,p.RecordsInspected,expectedRecords,p.RecordsDurable,expectedRecords,p.Elapsed.Round(time.Millisecond))
    }
   })
  if err!=nil{return fmt.Errorf("FI continuous private recovery: %w",err)}
  if result.Windows<=0||result.Records!=expectedRecords||result.SourceID!=sourceID||
   result.GenerationID!=generationID||result.ReceiptSHA256==""{
   return errors.New("FI continuous private: final verification identity/count mismatch")
  }
  fmt.Printf("FI REAL BACKLOG PRIVATE COMPLETE windows=%d records=%d bytes=%d elapsed=%s; NO Accepted journal or authoritative publication\n",
   result.Windows,result.Records,result.DataBytes,time.Since(began).Round(time.Millisecond))
  return nil
 }
 var prepared *recordingest.PreparedGeneration
 if indexedPrivate {
  fmt.Printf("FI REAL BACKLOG INDEXED PRIVATE selective custody prefix start_window=%d count=%d; full FIGT verification deferred to final acceptance\n",startWindow,maxWindows)
  prepared,err=recordingest.LoadIndexedBacklogPrivateWindows(ctx,canonical,loadConfig,generation,limits,startWindow,maxWindows)
 }else if streamLoader {
  if maxWindows<1||maxWindows>8 {
   return errors.New("stream-loader currently requires 1..8 requested windows")
  }
  prepared,err=recordingest.LoadRecordedGenerationSelectedWindows(
   loadConfig,generation,limits,startWindow,maxWindows,
   func(p recordingest.BacklogStreamProgress){
    if p.BatchesSeen==1 || p.BatchesSeen%128==0 || p.BatchesSeen==expectedBatches {
     fmt.Printf("FI REAL BACKLOG STREAM inspected_batches=%d/%d records=%d/%d bytes=%d retained_batches=%d current_window=%d elapsed=%s\n",
      p.BatchesSeen,expectedBatches,p.RecordsSeen,expectedRecords,p.DataBytesSeen,
      p.RetainedBatches,p.WindowIndex,time.Since(loadStarted).Round(time.Millisecond))
    }
   })
 }else{
  prepared,err=recordingest.LoadRecordedGeneration(loadConfig,generation)
 }
 if err!=nil{return fmt.Errorf("FI signed custody load: %w",err)}
 defer prepared.Close()
 if prepared.Receipt.RecordCount!=expectedRecords || prepared.Receipt.BatchCount!=expectedBatches ||
  prepared.Receipt.Descriptor.SourceID!=source || prepared.Receipt.Descriptor.GenerationID!=generation {
  return fmt.Errorf("FI signed receipt does not match target records=%d batches=%d",prepared.Receipt.RecordCount,prepared.Receipt.BatchCount)
 }
 windows,err:=recordingest.DescribeBacklogWindows(prepared,limits);if err!=nil{return err}
 if indexedPrivate {
  fmt.Printf("FI REAL BACKLOG INDEXED selected prefix hashes match previously authenticated shadow index records=%d batches=%d windows=%d receipt=%s partial_read=%s; NOT full transfer revalidation\n",
   expectedRecords,expectedBatches,len(windows),prepared.ReceiptSHA256,time.Since(loadStarted).Round(time.Millisecond))
 }else{
  fmt.Printf("FI REAL BACKLOG verified signed receipt records=%d batches=%d windows=%d receipt=%s load=%s\n",
   expectedRecords,expectedBatches,len(windows),prepared.ReceiptSHA256,time.Since(loadStarted).Round(time.Millisecond))
 }
 if startWindow>=len(windows){return fmt.Errorf("start window %d outside signed window count %d",startWindow,len(windows))}
 end:=startWindow+maxWindows
 if maxWindows==0||end>len(windows){end=len(windows)}
 if indexedPrivate && end==len(windows){return errors.New("indexed-private must not finish generation without complete signed custody revalidation")}
 if preflightOnly {
  fmt.Printf("FI REAL BACKLOG PREFLIGHT ONLY selected_windows=%d..%d; no private writes, no accepted record, no authoritative changes\n",startWindow,end-1)
  return nil
 }
 var records uint64
 started:=time.Now()
 for i:=startWindow;i<end;i++{
  window:=windows[i]
  var times [4]time.Duration
  tick:=time.Now()
  if _,err:=recordingest.MaterializeBacklogWindow(ctx,prepared,limits,i,private);err!=nil{return fmt.Errorf("window %d artifact: %w",i,err)}
  times[0]=time.Since(tick)
  tick=time.Now()
  if err:=recordingest.RecordVerifiedBacklogArtifactWindow(ctx,canonical,prepared,limits,i,private);err!=nil{return fmt.Errorf("window %d artifact ledger: %w",i,err)}
  times[1]=time.Since(tick)
  tick=time.Now()
  if err:=recordingest.StageVerifiedBacklogSourceWindow(ctx,canonical,prepared,limits,i,private);err!=nil{return fmt.Errorf("window %d source: %w",i,err)}
  times[2]=time.Since(tick)
  tick=time.Now()
  if err:=recordingest.StageBacklogTypedWindow(ctx,reader,canonical,prepared,limits,i,private);err!=nil{return fmt.Errorf("window %d typed: %w",i,err)}
  times[3]=time.Since(tick)
  records=window.EndRecord
  fmt.Printf("FI REAL BACKLOG DURABLE window=%d/%d batches=%d..%d records=%d..%d artifact=%s ledger=%s source=%s typed=%s elapsed=%s\n",
   i+1,len(windows),window.StartBatch,window.EndBatch,window.StartRecord,window.EndRecord,
   times[0].Round(time.Millisecond),times[1].Round(time.Millisecond),times[2].Round(time.Millisecond),
   times[3].Round(time.Millisecond),time.Since(started).Round(time.Millisecond))
 }
 if end==len(windows){
  verified,err:=recordingest.VerifyCompleteBacklogTypedGeneration(ctx,reader,prepared,limits)
  if err!=nil{return fmt.Errorf("FI whole-generation private verification: %w",err)}
  fmt.Printf("FI REAL BACKLOG PRIVATE COMPLETE windows=%d records=%d bytes=%d\n",verified.Windows,verified.Records,verified.DataBytes)
 }else {
  fmt.Printf("FI REAL BACKLOG PAUSED completed_to_window=%d durable_records_through=%d/%d; no Accepted journal or authoritative writes\n",
   end,records,expectedRecords)
 }
 if strings.TrimSpace(prepared.ReceiptSHA256)==""{return errors.New("missing receipt")}
 return nil
}

func main(){if err:=run();err!=nil{fmt.Fprintln(os.Stderr,"ERROR:",err);os.Exit(1)}}
