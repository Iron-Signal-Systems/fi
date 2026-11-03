//go:build freebsd

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package main

// The privileged FI publisher is a separately invoked, opt-in utility.
// It never performs private recovery, and it cannot publish a partial
// signed generation. SQL rights remain in the controlled publisher role,
// not in the append-only fi_ingest worker identity.
import (
 "context"
 "crypto/rand"
 "encoding/hex"
 "errors"
 "flag"
 "fmt"
 "os"
 "os/signal"
 "path/filepath"
 "syscall"
 "time"

 "github.com/Iron-Signal-Systems/fi/go/internal/recordingest"
 "github.com/jackc/pgx/v5"
)

const (
 sourceID="iss-fs-22a.iss.local"
 generationID="20261030T000032.061323100Z-3e38b2210771462c"
 expectedRecords=uint64(15140785)
 expectedBatches=uint64(8399)
)
func main(){if err:=run();err!=nil{fmt.Fprintln(os.Stderr,"FI SOR PUBLISH STOP:",err);os.Exit(1)}}

func checkedDirectory(path string)error{
 if !filepath.IsAbs(path)||filepath.Clean(path)!=path{return fmt.Errorf("absolute canonical directory required: %q",path)}
 s,err:=os.Lstat(path)
 if err!=nil{return err}
 if !s.IsDir() || s.Mode()&os.ModeSymlink!=0 || s.Mode().Perm()&0022!=0{
  return fmt.Errorf("FI SoR publisher: untrusted or writable custody path %q",path)
 }
 return nil
}
func checkedClusterIdentity(ctx context.Context,conn *pgx.Conn)(string,string,time.Time,error){
 var db,user string
 var started time.Time
 err:=conn.QueryRow(ctx,"SELECT current_database(),current_user,pg_postmaster_start_time()").Scan(&db,&user,&started)
 return db,user,started,err
}
func publisherAttemptID()(string,error){
 var raw [20]byte
 if _,err:=rand.Read(raw[:]);err!=nil{return "",err}
 return "fi-remapped-"+hex.EncodeToString(raw[:]),nil
}

func run()error{
 var source,generation,verifyDSN,publishDSN,custody,recorded,windowProfile,confirm string
 var namespaces,preflightOnly,apply bool
 var maxRuntime time.Duration
 flag.StringVar(&source,"source","","exact original FI source ID")
 flag.StringVar(&generation,"generation-id","","exact original signed generation ID")
 flag.StringVar(&verifyDSN,"verify-postgres","","append-only fi_ingest PostgreSQL DSN")
 flag.StringVar(&publishDSN,"publisher-postgres","","separately authorized SoR publisher PostgreSQL DSN")
 flag.StringVar(&custody,"custody-root","/var/db/fi/custody/generation","original immutable FIGT custody")
 flag.StringVar(&recorded,"recorded-root","/var/db/fi/custody/recorded","original recorded signed receipts")
 flag.StringVar(&windowProfile,"window-profile","W128","exact private checkpoint profile: W32/W64/W96/W128")
 flag.BoolVar(&namespaces,"source-namespaces",false,"recorded receipts use per-source namespace")
 flag.BoolVar(&preflightOnly,"preflight-only",false,"cheap read-only checkpoint completeness, NO custody scan or SQL writes")
 flag.BoolVar(&apply,"apply",false,"actually publish after full trust and private verification")
 flag.StringVar(&confirm,"confirm-generation","","must repeat the pinned generation ID when -apply")
 flag.DurationVar(&maxRuntime,"max-runtime",0,"optional maximum runtime, 0 = operator-controlled")
 flag.Parse()
 if flag.NArg()!=0 || source!=sourceID||generation!=generationID||verifyDSN=="" ||
  (apply && publishDSN=="") || (apply && confirm!=generationID) ||
  (preflightOnly && apply) || maxRuntime<0 || maxRuntime>24*time.Hour {
  return errors.New("FI publisher: pinned source/generation, verifier DSN, explicit owner DSN and apply confirmation required")
 }
 for _,p:=range []string{custody,recorded}{
  if err:=checkedDirectory(p);err!=nil{return err}
 }
 limits:=recordingest.BacklogWindowLimits{}
 switch windowProfile{
 case "W32":limits=recordingest.BacklogWindowLimits{MaxRecords:32768,MaxDataBytes:256<<20}
 case "W64":limits=recordingest.BacklogWindowLimits{MaxRecords:65536,MaxDataBytes:1<<30}
 case "W96":limits=recordingest.BacklogWindowLimits{MaxRecords:98304,MaxDataBytes:1<<30}
 case "W128":limits=recordingest.BacklogWindowLimits{MaxRecords:131072,MaxDataBytes:1<<30}
 default:return errors.New("FI publisher: unknown window checkpoint profile")
 }
 ctx,stopSignal:=signal.NotifyContext(context.Background(),os.Interrupt,syscall.SIGTERM)
 defer stopSignal()
 var cancel context.CancelFunc
 if maxRuntime>0{ctx,cancel=context.WithTimeout(ctx,maxRuntime)}else{ctx,cancel=context.WithCancel(ctx)}
 defer cancel()
 verify,err:=pgx.Connect(ctx,verifyDSN)
 if err!=nil{return err}
 defer verify.Close(context.Background())
 db,user,clusterStarted,err:=checkedClusterIdentity(ctx,verify)
 if err!=nil{return err}
 if db!="fi"||user!="fi_ingest"{return errors.New("FI publisher: verifier must be fi_ingest in fi database")}
 // Fast fail on the already observed partial 910,962/15,140,785 baseline.
 // It does NOT decide source trust or Accepted eligibility. The complete
 // signed custody loader and full private verifier decide that later.
 var declared,declaredBatches int64
 var signedReceipt []byte
 err=verify.QueryRow(ctx,`SELECT record_count,batch_count,receipt_sha256
 FROM fi_recovery_projection.recorded_generation
 WHERE source_id=$1 AND generation_id=$2`,source,generation).Scan(&declared,&declaredBatches,&signedReceipt)
 if err!=nil{return fmt.Errorf("FI publisher: no exact private recorded generation: %w",err)}
 if declared!=int64(expectedRecords)||declaredBatches!=int64(expectedBatches)||len(signedReceipt)!=32{
  return errors.New("FI publisher: private generation source/batch/receipt mismatch")
 }
 var countWindows int64
 var sumRecords int64
 err=verify.QueryRow(ctx,`SELECT count(*),coalesce(sum(committed_records),0)
 FROM fi_recovery.typed_window WHERE receipt_sha256=$1`,signedReceipt).Scan(&countWindows,&sumRecords)
 if err!=nil{return err}
 fmt.Printf("FI SOR READINESS source=%s generation=%s durable_windows=%d committed_private_records=%d expected=%d authoritative=unverified\n",
  source,generation,countWindows,sumRecords,expectedRecords)
 if sumRecords!=int64(expectedRecords){
  return fmt.Errorf("FI publisher: private generation incomplete %d/%d; no signed scan or authoritative writes attempted",sumRecords,expectedRecords)
 }
 // Marker counts can be forged or stale; they are ONLY an early failure
 // filter, never proof. The final publisher verifies every exact descriptor
 // and every persisted source/projection identity.
 if preflightOnly {
  fmt.Println("FI SOR READINESS ONLY: private prefix counts complete; NOT verified or Accepted")
  return nil
 }
 if !apply{
  fmt.Println("FI SOR NO WRITES: use -apply with explicit confirmed generation after privileged role is provisioned")
  return nil
 }
 publish,err:=pgx.Connect(ctx,publishDSN)
 if err!=nil{return err}
 defer publish.Close(context.Background())
 publisherDB,publisherUser,publisherStart,err:=checkedClusterIdentity(ctx,publish)
 if err!=nil{return err}
 if publisherDB!="fi" || publisherUser=="" || publisherUser=="fi_ingest" ||
  !publisherStart.Equal(clusterStarted) {
  return errors.New("FI publisher: publisher must be a distinct privileged role on SAME fi PostgreSQL cluster")
 }
 fmt.Printf("FI SOR PUBLISH AUTHENTICATING source=%s generation=%s profile=%s; complete signed FIGT custody scan follows\n",
  source,generation,windowProfile)
 started:=time.Now()
 load:=recordingest.GenerationLoadConfig{
  CustodyRoot:custody,RecordedRoot:recorded,SourceID:source,SourceNamespaces:namespaces,
  MaxCanonicalBytes:68719476736,MaxEncodedBytes:68719476736,MaxManifestBytes:1048576,
 }
 // One bounded window is staged (not all 15M source records); the loader
 // still verifies the full original signed transport. No JSONL relational
 // re-projection occurs during publication.
 prepared,err:=recordingest.LoadRecordedGenerationSelectedWindows(load,generation,limits,0,1,nil)
 if err!=nil{return fmt.Errorf("FI publisher: signed original custody validation: %w",err)}
 defer prepared.Close()
 if prepared.Receipt.RecordCount!=expectedRecords ||
  prepared.Receipt.BatchCount!=expectedBatches ||
  prepared.Receipt.Descriptor.SourceID!=sourceID ||
  prepared.Receipt.Descriptor.GenerationID!=generationID{
  return errors.New("FI publisher: post-signature source identity disagreement")
 }
 if !stringsEqualHex(prepared.ReceiptSHA256,signedReceipt){
  return errors.New("FI publisher: original signed receipt differs from private database")
 }
 fmt.Printf("FI SOR PUBLISH SIGNED VERIFIED records=%d batches=%d elapsed=%s\n",
  prepared.Receipt.RecordCount,prepared.Receipt.BatchCount,time.Since(started).Round(time.Millisecond))
 attemptID,err:=publisherAttemptID()
 if err!=nil{return err}
 result,err:=recordingest.PromoteVerifiedBacklogToPopulatedSoR(ctx,verify,publish,prepared,limits,attemptID)
 if err!=nil{return fmt.Errorf("FI publisher: no confirmed Accepted: %w",err)}
 if result.Outcome!="Accepted"&&result.Outcome!="AlreadyAccepted"{
  return errors.New("FI publisher: unexpected outcome")
 }
 fmt.Printf("FI SOR PUBLISHED source=%s generation=%s outcome=%s committed_source_records=%d total_wall=%s\n",
  result.SourceID,result.GenerationID,result.Outcome,result.RecordsCommitted,
  time.Since(started).Round(time.Millisecond))
 return nil
}
func stringsEqualHex(value string,digest []byte)bool{
 decoded,err:=hex.DecodeString(value)
 if err!=nil{return false}
 if len(decoded)!=len(digest){return false}
 var diff byte
 for i:=range digest{diff |= decoded[i]^digest[i]}
 return diff==0
}
