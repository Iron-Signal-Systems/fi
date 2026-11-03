package recordingest

import (
 "crypto/sha256"
 "encoding/hex"
 "os"
 "path/filepath"
 "testing"
)

func TestBacklogVerifiedCacheMarkerAtomicAndReceiptBound(t *testing.T){
 root:=t.TempDir()
 receipt:=sha256.Sum256([]byte("original signed receipt identity"))
 transfer:=sha256.Sum256([]byte("original signed custody transfer"))
 digest:=hex.EncodeToString(receipt[:])
 transferHex:=hex.EncodeToString(transfer[:])
 pending,err:=backlogVerifiedCacheBegin(root,digest)
 if err!=nil{t.Fatal(err)}
 if _,err:=backlogVerifiedCacheOpen(root,digest,transferHex,2,6,100);err==nil{
  t.Fatal("uncommitted partial cache was opened")
 }
 data:=[]byte("signed artifact byte sequence")
 manifest:=[]byte("original signed JSON manifest bytes")
 if err:=writeBacklogStageFile(backlogCacheBatchData(pending,0),data);err!=nil{t.Fatal(err)}
 if err:=writeBacklogStageFile(backlogCacheBatchManifest(pending,0),manifest);err!=nil{t.Fatal(err)}
 if err:=backlogVerifiedCacheCommit(root,pending,digest,transferHex,2,6,100);err!=nil{t.Fatal(err)}
 dir,err:=backlogVerifiedCacheOpen(root,digest,transferHex,2,6,100)
 if err!=nil{t.Fatal(err)}
 rawDigest:=sha256.Sum256(manifest)
 if _,err:=backlogVerifiedCacheManifest(dir,0,hex.EncodeToString(rawDigest[:]),1<<20);err!=nil{t.Fatal(err)}
 if _,err:=backlogVerifiedCacheOpen(root,digest,transferHex,2,7,100);err==nil{
  t.Fatal("receipt row count mismatch was silently accepted")
 }
 if _,err:=backlogVerifiedCacheBegin(root,digest);err==nil{
  t.Fatal("an already authenticated cache was overwritable")
 }
 if err:=os.WriteFile(filepath.Join(dir,"verified.json"),[]byte("{}"),0600);err!=nil{t.Fatal(err)}
 if _,err:=backlogVerifiedCacheOpen(root,digest,transferHex,2,6,100);err==nil{
  t.Fatal("corrupt verified-cache marker accepted")
 }
}
func TestBacklogVerifiedCacheRejectsUnsafeRoot(t *testing.T){
 root:=t.TempDir()
 if err:=os.Chmod(root,0755);err!=nil{t.Fatal(err)}
 if _,err:=backlogVerifiedCacheBegin(root,"012345");err==nil{
  t.Fatal("world-accessible cached custody root was accepted")
 }
}
