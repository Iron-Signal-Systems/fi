package backendinstall

import (
    "bytes"
    "os"
    "path/filepath"
    "testing"
)
func TestC1RAMFSTABAtomicAppendPreservesUnrelatedEntries(t *testing.T){
    dir:=t.TempDir()
    path:=filepath.Join(dir,"fi-ingest.fstab")
    original:=[]byte("# keep unmodified\n/custody /target nullfs ro 0 0")
    if e:=os.WriteFile(path,original,0640);e!=nil{t.Fatal(e)}
    target:="/test/fi-ingest/var/run/fi-c1-handoff"
    entry:="/var/run/fi-c1-handoff "+target+" nullfs rw 0 0"
    staged,e:=c1PlanStagedFSTAB(path,target,entry)
    if e!=nil{t.Fatal(e)}
    got,e:=os.ReadFile(path)
    if e!=nil||!bytes.Equal(got,original){
        t.Fatal("C1 fstab install altered unrelated entries before atomic publish")
    }
    if e=c1ApplyStagedFSTAB(staged);e!=nil{t.Fatal(e)}
    data,e:=os.ReadFile(path)
    if e!=nil{t.Fatal(e)}
    expected:=append(append([]byte{},original...),[]byte("\n"+entry+"\n")...)
    if !bytes.Equal(data,expected){t.Fatalf("C1 fstab original bytes rewritten: %q",data)}
    again,e:=c1PlanStagedFSTAB(path,target,entry)
    if e!=nil||again.temporary!=""{
        t.Fatalf("idempotent exact entry unexpectedly staged again: %+v %v",again,e)
    }
}
func TestC1RAMFSTABPreflightRejectsChangedOrForeignEntry(t *testing.T){
    dir:=t.TempDir()
    path:=filepath.Join(dir,"fi-sor.fstab")
    entry:="/var/run/fi-c1-handoff /test/fi-sor/ram nullfs ro 0 0"
    target:="/test/fi-sor/ram"
    if e:=os.WriteFile(path,[]byte("# original\n"),0644);e!=nil{t.Fatal(e)}
    stage,e:=c1PlanStagedFSTAB(path,target,entry)
    if e!=nil{t.Fatal(e)}
    defer os.Remove(stage.temporary)
    if e=os.WriteFile(path,[]byte("# changed after staged preflight\n"),0644);e!=nil{t.Fatal(e)}
    if e=c1ApplyStagedFSTAB(stage);e==nil{
        t.Fatal("staged C1 fstab silently overwrote changed existing content")
    }
    if e=os.WriteFile(path,[]byte("/foreign /test/fi-sor/ram nullfs rw 0 0\n"),0644);e!=nil{t.Fatal(e)}
    if _,e=c1PlanStagedFSTAB(path,target,entry);e==nil{
        t.Fatal("C1 fstab accepted writable/foreign SoR mount")
    }
}
func TestC1RAMFSTABRejectsSymlinkAndDuplicate(t *testing.T){
    dir:=t.TempDir()
    original:=filepath.Join(dir,"real.fstab")
    alias:=filepath.Join(dir,"alias.fstab")
    target:="/test/fi-sor/ram"
    entry:="/var/run/fi-c1-handoff "+target+" nullfs ro 0 0"
    if e:=os.WriteFile(original,[]byte("# valid\n"),0600);e!=nil{t.Fatal(e)}
    if e:=os.Symlink(original,alias);e!=nil{t.Fatal(e)}
    if _,e:=c1PlanStagedFSTAB(alias,target,entry);e==nil{
        t.Fatal("C1 fstab accepted symlink destination")
    }
    if e:=os.WriteFile(original,[]byte(entry+"\n"+entry+"\n"),0600);e!=nil{t.Fatal(e)}
    if _,e:=c1PlanStagedFSTAB(original,target,entry);e==nil{
        t.Fatal("C1 fstab accepted duplicate existing entry")
    }
}
