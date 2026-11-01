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
 var namespaces, enable bool
 var maxWindows, startWindow int
 flag.StringVar(&source,"source","","exact original signed FI source")
 flag.StringVar(&generation,"generation-id","","exact original signed FI generation")
 flag.StringVar(&pg,"postgres","","FI ingest PostgreSQL connection string")
 flag.StringVar(&custody,"custody-root","/var/db/fi/custody/generation","original immutable FIGT custody")
 flag.StringVar(&recorded,"recorded-root","/var/db/fi/custody/recorded","original immutable recorded receipts")
 flag.StringVar(&private,"private-root","","pre-created private 0700 recovery directory")
 flag.BoolVar(&namespaces,"source-namespaces",false,"recorded receipt uses per-source directory")
 flag.BoolVar(&enable,"private-writes",false,"explicitly enable PRIVATE recovery writes")
 flag.IntVar(&maxWindows,"max-windows",2,"private windows to process per invocation; 0 means to final window")
 flag.IntVar(&startWindow,"start-window",0,"original signed window index to resume from")
 flag.Parse()
 if flag.NArg()!=0 || source!=sourceID || generation!=generationID ||
  pg=="" || private=="" || !enable || maxWindows<0 || maxWindows>1000 || startWindow<0 {
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
 ctx,stop:=context.WithCancel(context.Background());defer stop()
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

 fmt.Printf("FI REAL BACKLOG loading authenticated custody source=%s generation=%s\n",source,generation)
 loadStarted:=time.Now()
 prepared,err:=recordingest.LoadRecordedGeneration(recordingest.GenerationLoadConfig{
  CustodyRoot:custody,RecordedRoot:recorded,SourceID:source,SourceNamespaces:namespaces,
  MaxCanonicalBytes:68719476736,MaxEncodedBytes:68719476736,MaxManifestBytes:1048576,
 },generation)
 if err!=nil{return fmt.Errorf("FI signed custody load: %w",err)}
 defer prepared.Close()
 if prepared.Receipt.RecordCount!=expectedRecords || prepared.Receipt.BatchCount!=expectedBatches ||
  prepared.Receipt.Descriptor.SourceID!=source || prepared.Receipt.Descriptor.GenerationID!=generation {
  return fmt.Errorf("FI signed receipt does not match target records=%d batches=%d",prepared.Receipt.RecordCount,prepared.Receipt.BatchCount)
 }
 limits:=recordingest.BacklogWindowLimits{MaxRecords:32768,MaxDataBytes:256<<20}
 windows,err:=recordingest.DescribeBacklogWindows(prepared,limits);if err!=nil{return err}
 fmt.Printf("FI REAL BACKLOG verified signed receipt records=%d batches=%d windows=%d receipt=%s load=%s\n",
  expectedRecords,expectedBatches,len(windows),prepared.ReceiptSHA256,time.Since(loadStarted).Round(time.Millisecond))
 if startWindow>=len(windows){return fmt.Errorf("start window %d outside signed window count %d",startWindow,len(windows))}
 end:=startWindow+maxWindows
 if maxWindows==0||end>len(windows){end=len(windows)}
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
