// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package volumecustody

import (
 "context"
 "encoding/json"
 "errors"
 "os"
 "path/filepath"
 "strings"
 "testing"

 "github.com/Iron-Signal-Systems/fi/go/internal/windows/volumeepoch"
)

func writeTestCheckpoint(t *testing.T,dir string,c volumeepoch.Checkpoint) string {
 t.Helper()
 data,err:=json.Marshal(c)
 if err!=nil{t.Fatal(err)}
 path:=filepath.Join(dir,"fi-volume-"+c.EnrollmentID+".checkpoint.json")
 if err:=os.WriteFile(path,append(data,'\n'),0600);err!=nil{t.Fatal(err)}
 return path
}
func testWindowState(t *testing.T) (*WindowsVolumeState,volumeepoch.Checkpoint,string){
 t.Helper()
 cp,_,_:=custodyFixture()
 dir:=t.TempDir()
 path:=writeTestCheckpoint(t,dir,cp)
 return &WindowsVolumeState{Directory:dir},cp,path
}
func TestWindowsVolumeStateLeaseAndPersistedCAS(t *testing.T){
 s,cp,path:=testWindowState(t)
 ctx:=context.Background()
 if _,err:=s.Load(ctx,"data");!errors.Is(err,ErrVolumeStateBusy){t.Fatalf("unlocked load allowed: %v",err)}
 lease,err:=s.Acquire(ctx,"data");if err!=nil{t.Fatal(err)}
 other:=&WindowsVolumeState{Directory:s.Directory}
 if _,err:=other.Acquire(ctx,"data");!errors.Is(err,ErrVolumeStateBusy){
  t.Fatalf("cross-instance lock did not refuse concurrent owner: %v",err)
 }
 initial,err:=s.Load(ctx,"data");if err!=nil||initial!=cp{t.Fatalf("read stored checkpoint: %+v %v",initial,err)}
 next:=cp;next.NextUSN="2500"
 if err:=s.Commit(ctx,cp,next);err!=nil{t.Fatal(err)}
 if _,err:=os.Stat(path);err!=nil{t.Fatalf("checkpoint not persisted: %v",err)}
 current,err:=s.Load(ctx,"data")
 if err!=nil||current!=next{t.Fatalf("checkpoint not reloaded: %+v %v",current,err)}
 if err:=s.Commit(ctx,cp,next);!errors.Is(err,ErrVolumeCheckpointConflict){
  t.Fatalf("stale CAS overwrote existing checkpoint: %v",err)
 }
 if err:=lease.Release();err!=nil{t.Fatal(err)}
 if err:=lease.Release();err!=nil{t.Fatal(err)}
 if _,err:=s.Load(ctx,"data");!errors.Is(err,ErrVolumeStateBusy){t.Fatalf("released lease still authorized: %v",err)}
 acquired,err:=other.Acquire(ctx,"data");if err!=nil{t.Fatalf("released native lease blocked: %v",err)}
 if err:=acquired.Release();err!=nil{t.Fatal(err)}
}
func TestWindowsVolumeStateRejectsInterruptedPendingAndPreservesOriginal(t *testing.T){
 s,cp,path:=testWindowState(t)
 ctx:=context.Background()
 l,err:=s.Acquire(ctx,"data");if err!=nil{t.Fatal(err)}
 defer l.Release()
 pending:=filepath.Join(s.Directory,"fi-volume-data.checkpoint.pending")
 if err:=os.WriteFile(pending,[]byte("incomplete"),0600);err!=nil{t.Fatal(err)}
 next:=cp;next.NextUSN="2500"
 if err:=s.Commit(ctx,cp,next);!errors.Is(err,ErrVolumeStateUntrusted){
  t.Fatalf("interrupted transaction was overwritten: %v",err)
 }
 current,err:=s.Load(ctx,"data")
 if err!=nil||current!=cp{t.Fatalf("pending file changed checkpoint: %+v %v",current,err)}
 if data,err:=os.ReadFile(pending);err!=nil||string(data)!="incomplete" {
  t.Fatalf("pending evidence was destroyed: %q %v",data,err)
 }
 if _,err:=os.Stat(path);err!=nil{t.Fatal(err)}
}
func TestWindowsVolumeStateRejectsCorruptCheckpointAndBadAdvance(t *testing.T){
 s,cp,path:=testWindowState(t)
 ctx:=context.Background()
 l,err:=s.Acquire(ctx,"data");if err!=nil{t.Fatal(err)}
 defer l.Release()
 for _,raw:=range []string{
  "{", "{}","null", `{"version":"x"}`,
  strings.Repeat("x",maxVolumeCheckpointBytes+3),
 }{
  if err:=os.WriteFile(path,[]byte(raw),0600);err!=nil{t.Fatal(err)}
  if _,err:=s.Load(ctx,"data");!errors.Is(err,ErrVolumeStateUntrusted){
   t.Fatalf("malformed persistent checkpoint accepted: %q %v",raw[:min(20,len(raw))],err)
  }
 }
 writeTestCheckpoint(t,s.Directory,cp)
 for _,bad:=range []struct{
  name string
  mutate func(*volumeepoch.Checkpoint)
 }{
  {"rewind",func(x *volumeepoch.Checkpoint){x.NextUSN="1999"}},
  {"no movement",func(x *volumeepoch.Checkpoint){x.NextUSN=cp.NextUSN}},
  {"epoch jump",func(x *volumeepoch.Checkpoint){x.Epoch++}},
  {"journal swap",func(x *volumeepoch.Checkpoint){x.Identity.JournalID="999"}},
  {"enrollment swap",func(x *volumeepoch.Checkpoint){x.EnrollmentID="other"}},
  {"invalid decimal",func(x *volumeepoch.Checkpoint){x.NextUSN="02000"}},
 }{
  t.Run(bad.name,func(t *testing.T){
   next:=cp;bad.mutate(&next)
   if err:=s.Commit(ctx,cp,next);err==nil{t.Fatal("unsafe cursor replacement permitted")}
   fresh,err:=s.Load(ctx,"data");if err!=nil||fresh!=cp{t.Fatalf("bad CAS altered persistent checkpoint: %+v %v",fresh,err)}
  })
 }
}
func TestWindowsVolumeStateRejectsUntrustedDirectoryAndUnsafeEnrollment(t *testing.T){
 s,cp,_:=testWindowState(t)
 for _,id:=range []string{"","../data","Data","data/other",strings.Repeat("z",65)}{
  if _,err:=s.Acquire(context.Background(),id);!errors.Is(err,ErrUnconfiguredPass){
   t.Fatalf("untrusted lease ID accepted: %q %v",id,err)
  }
 }
 bad:=&WindowsVolumeState{Directory:filepath.Join(s.Directory,"missing")}
 if _,err:=bad.Acquire(context.Background(),"data");!errors.Is(err,ErrVolumeStateUntrusted){
  t.Fatalf("missing state directory accepted: %v",err)
 }
 if _,err:=bad.Load(context.Background(),cp.EnrollmentID);!errors.Is(err,ErrVolumeStateUntrusted){
  t.Fatalf("missing state directory accepted for load: %v",err)
 }
}
func TestWindowsVolumeStateIntegratesWithOneWindowCoordinator(t *testing.T){
 s,cp,_:=testWindowState(t)
 h:=newPassHarness(t)
 deps:=h.dep()
 deps.Lease=s
 deps.Store=s
 deps.Publisher=oneWindowPublisher(h.spoolDir)
 result,err:=ProcessOneWindow(context.Background(),cp.EnrollmentID,deps)
 if err!=nil||!result.CheckpointCommitted||!result.Published {
  t.Fatalf("native durable CAS did not follow verified FI source custody: %+v %v",result,err)
 }
 lease,err:=s.Acquire(context.Background(),"data")
 if err!=nil{t.Fatal(err)}
 actual,err:=s.Load(context.Background(),"data")
 if err!=nil||actual.NextUSN!="2500"{t.Fatalf("durable checkpoint missing after fresh lease: %+v %v",actual,err)}
 if err:=lease.Release();err!=nil{t.Fatal(err)}
}
