//go:build freebsd

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Private H16 SHA-once experiment evidence-identity tests, no database needed.
package recordingest

import (
    "context"
    "os"
    "path/filepath"
    "testing"
    "time"

    "github.com/Iron-Signal-Systems/fi/go/internal/spool"
)

func TestPrivateBatchHashOnceRequiresVerifiedCloneContext(t *testing.T) {
    dir:=t.TempDir()
    name:=filepath.Join(dir,"batch-00000177.data")
    if err:=os.WriteFile(name,[]byte("{\"a\":1}\n"),0600);err!=nil {t.Fatal(err)}
    f,err:=os.Open(name)
    if err!=nil {t.Fatal(err)}
    defer f.Close()
    batch:=PreparedBatch{DataPath:name,Manifest:spool.Manifest{
       DataBytes:8,DataSHA256:"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    }}
    if proof,err:=privateReuseSignedBatchDigest(context.Background(),batch,f);err!=nil||proof!=nil{
        t.Fatalf("unproved ordinary ingest unexpectedly skipped SHA: proof=%v err=%v",proof,err)
    }
    identity,err:=deferredFileStat(name)
    if err!=nil {t.Fatal(err)}
    d:=&deferredBacklogWindow{pending:dir,sourceFiles:[]deferredFileIdentity{identity}}
    ctx:=context.WithValue(context.Background(),privateDeferredWindowKey{},d)
    proof,err:=privateReuseSignedBatchDigest(ctx,batch,f)
    if err!=nil || proof==nil {t.Fatalf("verified clone proof rejected: proof=%v err=%v",proof,err)}
    if err:=proof.check();err!=nil {t.Fatal(err)}
    wrong:=batch
    wrong.DataPath=filepath.Join(dir,"other.data")
    if p,err:=privateReuseSignedBatchDigest(ctx,wrong,f);p!=nil||err==nil{
        t.Fatalf("different file incorrectly accepted: %v %v",p,err)
    }
    changed:=batch
    changed.Manifest.DataBytes++
    if p,err:=privateReuseSignedBatchDigest(ctx,changed,f);p!=nil||err==nil{
        t.Fatalf("changed signed length incorrectly accepted: %v %v",p,err)
    }
    if err:=os.Chtimes(name,time.Now().Add(time.Second),time.Now().Add(time.Second));err!=nil {t.Fatal(err)}
    if err:=proof.check();err==nil {t.Fatal("modified clone mtime passed final evidence gate")}
}

func TestPrivateBatchHashOnceRejectsReplacedPath(t *testing.T) {
    dir:=t.TempDir()
    name:=filepath.Join(dir,"batch-00000178.data")
    content:=[]byte("{\"a\":1}\n")
    if err:=os.WriteFile(name,content,0600);err!=nil{t.Fatal(err)}
    f,err:=os.Open(name)
    if err!=nil{t.Fatal(err)}
    defer f.Close()
    identity,err:=deferredFileStat(name)
    if err!=nil{t.Fatal(err)}
    d:=&deferredBacklogWindow{pending:dir,sourceFiles:[]deferredFileIdentity{identity}}
    ctx:=context.WithValue(context.Background(),privateDeferredWindowKey{},d)
    batch:=PreparedBatch{DataPath:name,Manifest:spool.Manifest{
        DataBytes:int64(len(content)),DataSHA256:"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    }}
    proof,err:=privateReuseSignedBatchDigest(ctx,batch,f)
    if err!=nil || proof==nil {t.Fatal(err)}
    if err:=os.Remove(name);err!=nil{t.Fatal(err)}
    if err:=os.WriteFile(name,content,0600);err!=nil{t.Fatal(err)}
    if err:=proof.check();err==nil{t.Fatal("replaced path passed final evidence gate")}
}
