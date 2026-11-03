// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "os"
 "path/filepath"
)

type backlogVerifiedCacheMarker struct{
 ReceiptSHA256 string `json:"receipt_sha256"`
 TransferSHA256 string `json:"transfer_sha256"`
 BatchCount uint64 `json:"batch_count"`
 RecordCount uint64 `json:"record_count"`
 DataBytes uint64 `json:"data_bytes"`
}

// The data files and manifests in this cache are produced ONLY by the full
// authenticated FIGT transport reader. A marker is published atomically AFTER
// every original batch and the entire signed receipt/transfer have matched.
// The cache is benchmark INPUT, not an Accepted/SoR authority.
func backlogVerifiedCacheDirectory(root,receiptSHA string) string{
 return filepath.Join(root,"receipt-"+receiptSHA)
}
func backlogCacheBatchData(directory string,index int)string{
 return filepath.Join(directory,fmt.Sprintf("batch-%08d.data",index))
}
func backlogCacheBatchManifest(directory string,index int)string{
 return filepath.Join(directory,fmt.Sprintf("batch-%08d.manifest",index))
}
func backlogVerifiedCacheBegin(root,receiptSHA string)(string,error){
 if err:=verifyPrivateBacklogRoot(root);err!=nil{return "",err}
 dest:=backlogVerifiedCacheDirectory(root,receiptSHA)
 if _,err:=os.Lstat(dest);err==nil{
  return "",errors.New("FI verified cache: final receipt directory already exists (never overwrite)")
 }else if !errors.Is(err,os.ErrNotExist){return "",err}
 return os.MkdirTemp(root,".fi-verified-cache-pending-")
}
func backlogVerifiedCacheCommit(root,pending,receiptSHA,transferSHA string,batches,records,bytes uint64)error{
 if pending==""{return errors.New("FI verified cache: empty pending directory")}
 marker:=backlogVerifiedCacheMarker{ReceiptSHA256:receiptSHA,TransferSHA256:transferSHA,
  BatchCount:batches,RecordCount:records,DataBytes:bytes}
 encoded,err:=json.Marshal(marker)
 if err!=nil{return err}
 if err=writeBacklogStageFile(filepath.Join(pending,"verified.json"),encoded);err!=nil{return err}
 if err=syncBacklogStageDir(pending);err!=nil{return err}
 if err=os.Rename(pending,backlogVerifiedCacheDirectory(root,receiptSHA));err!=nil{return err}
 return syncBacklogStageDir(root)
}
func backlogVerifiedCacheOpen(root,receiptSHA,transferSHA string,batches,records,bytes uint64)(string,error){
 if err:=verifyPrivateBacklogRoot(root);err!=nil{return "",err}
 dest:=backlogVerifiedCacheDirectory(root,receiptSHA)
 if err:=verifyPrivateBacklogRoot(dest);err!=nil{return "",err}
 raw,err:=readBacklogStageFile(filepath.Join(dest,"verified.json"),4096)
 if err!=nil{return "",err}
 var marker backlogVerifiedCacheMarker
 if err=json.Unmarshal(raw,&marker);err!=nil{return "",err}
 if marker.ReceiptSHA256!=receiptSHA || marker.TransferSHA256!=transferSHA ||
   marker.BatchCount!=batches || marker.RecordCount!=records || marker.DataBytes!=bytes{
  return "",errors.New("FI verified cache: marker disagrees with original recorded receipt")
 }
 return dest,nil
}
func backlogVerifiedCacheManifest(directory string,index int,expectedHash string,limit uint64)([]byte,error){
 if limit==0||limit>1<<20{return nil,errors.New("FI verified cache: invalid manifest bound")}
 raw,err:=readBacklogStageFile(backlogCacheBatchManifest(directory,index),int64(limit))
 if err!=nil{return nil,err}
 digest:=sha256.Sum256(raw)
 if hex.EncodeToString(digest[:])!=expectedHash{
  return nil,fmt.Errorf("FI verified cache: signed manifest hash mismatch at batch %d",index)
 }
 return raw,nil
}
