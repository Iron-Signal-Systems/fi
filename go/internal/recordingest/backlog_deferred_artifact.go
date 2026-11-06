// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// EXPERIMENTAL PRIVATE ONLY: defer artifact authority until the same SQL
// transaction has verified every original signed data batch and its typed
// projection. Never permitted in ordinary ingest or Accepted publication.
package recordingest

import (
 "context"
 "crypto/sha256"
 "crypto/subtle"
 "encoding/binary"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "os"
 "path/filepath"
 "syscall"

 "github.com/jackc/pgx/v5"
)

type privateDeferredCloneKey struct{}
type privateDeferredWindowKey struct{}

func WithPrivateDeferredVerifiedClone(ctx context.Context) context.Context {
 if ctx==nil {return nil}
 return context.WithValue(ctx,privateDeferredCloneKey{},true)
}
func privateDeferredCloneEnabled(ctx context.Context) bool {
 return ctx!=nil && ctx.Value(privateDeferredCloneKey{})==true
}
func deferredWindowFromContext(ctx context.Context)*deferredBacklogWindow{
 if ctx==nil {return nil}
 p,_:=ctx.Value(privateDeferredWindowKey{}).(*deferredBacklogWindow)
 return p
}

// A staged clone is NOT a verified artifact. It is stored under an unpublished
// .window-building-* path and cannot receive an artifact marker before the
// typed reader finishes checking every signed manifest SHA256.
type deferredBacklogWindow struct {
 root string
 pending string
 ready string
 descriptor BacklogCheckpointDescriptor
 start, end int
 sourceFiles []deferredFileIdentity
 published bool
}
type deferredFileIdentity struct{
 path string
 dev uint64
 ino uint64
 size int64
 modtime int64
}

func (p *deferredBacklogWindow) check(ctx context.Context,d BacklogCheckpointDescriptor,index int,root string)error{
 if p==nil||ctx==nil{return errors.New("deferred clone: missing context/proof")}
 if err:=ctx.Err();err!=nil{return err}
 if p.root!=root||p.descriptor!=d||p.start!=d.StartBatch||p.end!=d.EndBatch||
  p.pending==""||p.ready!=filepath.Join(root,"receipt-"+d.ReceiptSHA256,fmt.Sprintf("window-%08d",index))||
  p.published {return errors.New("deferred clone: stale or wrong signed descriptor")}
 if err:=verifyPrivateBacklogRoot(p.pending);err!=nil{return err}
 return nil
}

func (p *deferredBacklogWindow) cleanup(){
 if p!=nil&&!p.published&&p.pending!="" {
  // Remove only the just-created unique private temp dir, never a ready
  // checkpoint or the caller-owned verified cache.
  _=os.RemoveAll(p.pending)
 }
}
func deferredFileStat(path string)(deferredFileIdentity,error){
 st,err:=os.Lstat(path)
 if err!=nil{return deferredFileIdentity{},err}
 if !st.Mode().IsRegular()||st.Mode().Perm()!=0600||st.Mode()&os.ModeSymlink!=0{
  return deferredFileIdentity{},fmt.Errorf("deferred clone: invalid regular private file %s",path)
 }
 x,ok:=st.Sys().(*syscall.Stat_t)
 if !ok{return deferredFileIdentity{},errors.New("deferred clone: missing native file identity")}
 return deferredFileIdentity{path:path,dev:uint64(x.Dev),ino:x.Ino,size:st.Size(),modtime:st.ModTime().UnixNano()},nil
}

// stageDeferredBacklogWindow clones exclusively from the already authenticated
// receipt-bound cache, writes and fsyncs signed manifests and descriptor, and
// leaves the directory UNPUBLISHED until typed ingestion validates its bytes.
// Existing published files are NEVER assumed verified by this path.
func stageDeferredBacklogWindow(ctx context.Context,g *PreparedGeneration,
 limits BacklogWindowLimits,index int,root,cacheDir string)(*deferredBacklogWindow,error){
 if ctx==nil||g==nil||cacheDir==""{return nil,errors.New("deferred clone: incomplete inputs")}
 if err:=ctx.Err();err!=nil{return nil,err}
 descs,err:=DescribeBacklogWindows(g,limits)
 if err!=nil{return nil,err}
 if index<0||index>=len(descs){return nil,errors.New("deferred clone: invalid index")}
 d:=descs[index]
 if err=verifyPrivateBacklogRoot(root);err!=nil{return nil,err}
 if err=verifyPrivateBacklogRoot(cacheDir);err!=nil{return nil,err}
 generationDir:=filepath.Join(root,"receipt-"+d.ReceiptSHA256)
 if err=os.Mkdir(generationDir,0700);err!=nil&&!os.IsExist(err){return nil,err}
 if err=verifyPrivateBacklogRoot(generationDir);err!=nil{return nil,err}
 ready:=filepath.Join(generationDir,fmt.Sprintf("window-%08d",index))
 if _,err=os.Lstat(ready);err==nil{
  // A crashed earlier trial may have published the artifact but failed SQL.
  // The caller must then use the original full-hash verification path.
  return nil,nil
 }else if !os.IsNotExist(err){return nil,err}
 pending,err:=os.MkdirTemp(generationDir,".window-building-deferred-")
 if err!=nil{return nil,err}
 p:=&deferredBacklogWindow{root:root,pending:pending,ready:ready,
  descriptor:d,start:d.StartBatch,end:d.EndBatch,
  sourceFiles:make([]deferredFileIdentity,0,d.EndBatch-d.StartBatch)}
 success:=false
 defer func(){if !success {p.cleanup()}}()
 for i:=d.StartBatch;i<d.EndBatch;i++{
  if err=ctx.Err();err!=nil{return nil,err}
  b:=g.Batches[i]
  expected:=backlogCacheBatchData(cacheDir,i)
  if b.DataPath!=expected{return nil,fmt.Errorf("deferred clone: batch %d is not authenticated cache input",i)}
  sourceID,err:=deferredFileStat(expected)
  if err!=nil{return nil,err}
  if sourceID.size!=b.Manifest.DataBytes{return nil,fmt.Errorf("deferred clone: batch %d signed data length differs",i)}
  dst:=filepath.Join(pending,fmt.Sprintf("batch-%08d.data",i))
  if err=cloneDeferredDataFile(expected,dst,b.Manifest.DataBytes);err!=nil{
   return nil,fmt.Errorf("deferred clone: batch %d clone-required: %w",i,err)
  }
  outID,err:=deferredFileStat(dst)
  if err!=nil{return nil,err}
  if outID.size!=sourceID.size||outID.dev!=sourceID.dev||outID.ino==sourceID.ino{
   return nil,fmt.Errorf("deferred clone: batch %d not an independent same-filesystem inode",i)
  }
  p.sourceFiles=append(p.sourceFiles,outID)
  if len(b.ManifestRawBytes)==0||len(b.ManifestRawBytes)>1<<20{
   return nil,fmt.Errorf("deferred clone: batch %d missing signed manifest",i)
  }
  h:=sha256.Sum256(b.ManifestRawBytes)
  if hex.EncodeToString(h[:])!=b.ManifestSHA256{
   return nil,fmt.Errorf("deferred clone: batch %d manifest SHA differs",i)
  }
  if err=writeBacklogStageFile(filepath.Join(pending,fmt.Sprintf("batch-%08d.manifest",i)),b.ManifestRawBytes);err!=nil{return nil,err}
 }
 raw,err:=json.Marshal(d)
 if err!=nil{return nil,err}
 if err=writeBacklogStageFile(filepath.Join(pending,"descriptor.json"),raw);err!=nil{return nil,err}
 if err=syncBacklogStageDir(pending);err!=nil{return nil,err}
 if err=syncBacklogStageDir(generationDir);err!=nil{return nil,err}
 success=true
 return p,nil
}

// publish is invoked only after the typed path verified every exact LF-
// terminated source batch against its signed SHA. All file identities must
// remain unchanged. On a crash after rename but before SQL commit, restart
// rehashes all published bytes through the original public API.
func (p *deferredBacklogWindow) publish(ctx context.Context,d BacklogCheckpointDescriptor,index int,root string)error{
 if err:=p.check(ctx,d,index,root);err!=nil{return err}
 for _,before:=range p.sourceFiles{
  now,err:=deferredFileStat(before.path)
  if err!=nil{return err}
  if now.dev!=before.dev||now.ino!=before.ino||now.size!=before.size||now.modtime!=before.modtime{
   return errors.New("deferred clone: staged file metadata changed during verified ingest")
  }
 }
 raw,err:=readBacklogStageFile(filepath.Join(p.pending,"descriptor.json"),16<<10)
 if err!=nil{return err}
 var got BacklogCheckpointDescriptor
 if err=json.Unmarshal(raw,&got);err!=nil{return err}
 if got!=d{return errors.New("deferred clone: descriptor changed before publication")}
 if _,err=os.Lstat(p.ready);err==nil{
  return errors.New("deferred clone: completed artifact already exists")
 }else if !os.IsNotExist(err){return err}
 if err=os.Rename(p.pending,p.ready);err!=nil{return err}
 // Prevent cleanup from removing the published artifact on partial failure.
 p.published=true
 if err=syncBacklogStageDir(filepath.Dir(p.ready));err!=nil{return err}
 return nil
}

// The typed writer already holds the SAME receipt advisory transaction lock
// and has verified full source+typed record identities. This SQL marker goes
// into its transaction, not into an independently committed artifact tx.
func (p *deferredBacklogWindow) appendMarkerTx(ctx context.Context,tx pgx.Tx,d BacklogCheckpointDescriptor,index int)error{
 if p==nil||!p.published||p.descriptor!=d||tx==nil{return errors.New("deferred clone: cannot mark unverified/unpublished artifact")}
 receipt,err:=hex.DecodeString(d.ReceiptSHA256);if err!=nil{return err}
 transfer,err:=hex.DecodeString(d.TransferSHA256);if err!=nil{return err}
 digest,err:=hex.DecodeString(d.DigestSHA256);if err!=nil{return err}
 prev,err:=hex.DecodeString(d.PreviousDigestSHA256);if err!=nil{return err}
 var existing bool
 if err=tx.QueryRow(ctx,`SELECT EXISTS(SELECT 1 FROM fi_recovery.verified_artifact_window WHERE receipt_sha256=$1 AND window_index=$2)`,receipt,index).Scan(&existing);err!=nil{return err}
 if existing{return errors.New("deferred clone: prior artifact marker already exists")}
 var priorIndex,priorEndBatch int
 var priorEndRecord int64
 var priorDigest []byte
 if err=tx.QueryRow(ctx,`SELECT window_index,descriptor_sha256,end_batch,end_record
FROM fi_recovery.verified_artifact_window WHERE receipt_sha256=$1
ORDER BY window_index DESC LIMIT 1`,receipt).Scan(&priorIndex,&priorDigest,&priorEndBatch,&priorEndRecord);err!=nil{return err}
 if priorIndex+1!=index||subtle.ConstantTimeCompare(priorDigest,prev)!=1||
  priorEndBatch!=d.StartBatch||priorEndRecord!=int64(d.StartRecord){
  return errors.New("deferred clone: previous signed artifact checkpoint discontinuous")
 }
 _,err=tx.Exec(ctx,`INSERT INTO fi_recovery.verified_artifact_window(
 receipt_sha256,window_index,source_id,generation_id,
 transfer_sha256,descriptor_sha256,previous_digest_sha256,
 start_batch,end_batch,start_record,end_record,data_bytes)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
 receipt,index,d.SourceID,d.GenerationID,transfer,digest,prev,
 d.StartBatch,d.EndBatch,int64(d.StartRecord),int64(d.EndRecord),int64(d.DataBytes))
 return err
}

// The compiler-enforced static type of this lock key must match the existing
// receipt advisory lock used by StageBacklogTypedWindow.
var _ = binary.BigEndian
