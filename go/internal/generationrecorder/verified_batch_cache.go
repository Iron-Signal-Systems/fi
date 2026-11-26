// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Receiver-owned authenticated batch cache. Emit batch data and exact
// manifests DURING the receiver's existing signed FIGT semantic-validation
// pass. Publish only after the immutable recorder receipt is durable.
// fi-sor mounts this root READ-ONLY. This is recoverable acceleration, not
// a new custody authority and not a substitute for independent verifier B.
package generationrecorder

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type receiverVerifiedBatchWriter struct {
	root string
	pending string
	index uint64
	lastDataID string
}
type receiverVerifiedBatchMarker struct {
	ReceiptSHA256 string `json:"receipt_sha256"`
	TransferSHA256 string `json:"transfer_sha256"`
	BatchCount uint64 `json:"batch_count"`
	RecordCount uint64 `json:"record_count"`
	DataBytes uint64 `json:"data_bytes"`
}

func newReceiverVerifiedBatchWriter(root string)(*receiverVerifiedBatchWriter,error){
	if root==""{return nil,nil}
	if !filepath.IsAbs(root)||filepath.Clean(root)!=root{
		return nil,errors.New("FI receiver cache: absolute clean root required")
	}
	st,err:=os.Lstat(root)
	if err!=nil{return nil,err}
	if !st.IsDir()||st.Mode()&os.ModeSymlink!=0||st.Mode().Perm()&0022!=0{
		return nil,errors.New("FI receiver cache: private non-symlink directory required")
	}
	pending,err:=os.MkdirTemp(root,".fi-verified-cache-pending-")
	if err!=nil{return nil,err}
	return &receiverVerifiedBatchWriter{root:root,pending:pending},nil
}
func(w *receiverVerifiedBatchWriter)Discard(){
	if w!=nil&&w.pending!="" {
		_ = os.RemoveAll(w.pending)
		w.pending=""
	}
}
func(w *receiverVerifiedBatchWriter)Consume(name string,reader io.Reader,
	validate func(string,io.Reader)error)error{
	if w==nil||w.pending==""||reader==nil||validate==nil{
		return errors.New("FI receiver cache: invalid artifact consumer")
	}
	batchID,kind,err:=parseArtifactName(name)
	if err!=nil{return err}
	var filename string
	switch kind{
	case artifactKindData:
		if w.lastDataID!=""{return errors.New("FI receiver cache: prior manifest missing")}
		filename=fmt.Sprintf("batch-%08d.data",w.index)
	case artifactKindManifest:
		if batchID!=w.lastDataID{return errors.New("FI receiver cache: manifest/data identity mismatch")}
		filename=fmt.Sprintf("batch-%08d.manifest",w.index)
	default:
		return errors.New("FI receiver cache: unsupported artifact")
	}
	path:=filepath.Join(w.pending,filename)
	file,err:=os.OpenFile(path,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600)
	if err!=nil{return err}
	validateErr:=validate(name,io.TeeReader(reader,file))
	syncErr:=file.Sync()
	closeErr:=file.Close()
	if err:=errors.Join(validateErr,syncErr,closeErr);err!=nil{return err}
	if kind==artifactKindData{
		w.lastDataID=batchID
	}else{
		w.lastDataID=""
		w.index++
	}
	return nil
}
func(w *receiverVerifiedBatchWriter)Publish(result DurableResult)error{
	if w==nil||w.pending==""{return errors.New("FI receiver cache: missing provisional batch cache")}
	if w.lastDataID!=""||w.index!=result.Receipt.BatchCount||
		result.ReceiptSHA256==""||result.Receipt.TransferSHA256==""{
		return errors.New("FI receiver cache: incomplete or unbound verified batch count")
	}
	marker:=receiverVerifiedBatchMarker{
		ReceiptSHA256:result.ReceiptSHA256,
		TransferSHA256:result.Receipt.TransferSHA256,
		BatchCount:result.Receipt.BatchCount,
		RecordCount:result.Receipt.RecordCount,
		DataBytes:result.Receipt.DataBytes,
	}
	dest:=filepath.Join(w.root,"receipt-"+result.ReceiptSHA256)
	if info,err:=os.Lstat(dest);err==nil{
		if !info.IsDir()||info.Mode()&os.ModeSymlink!=0{
			return errors.New("FI receiver cache: existing final checkpoint unsafe")
		}
		raw,err:=os.ReadFile(filepath.Join(dest,"verified.json"))
		if err!=nil{return err}
		var existing receiverVerifiedBatchMarker
		if err:=json.Unmarshal(raw,&existing);err!=nil{return err}
		if existing!=marker{return errors.New("FI receiver cache: existing checkpoint conflicts with original signed receipt")}
		w.Discard()
		return nil
	}else if !errors.Is(err,os.ErrNotExist){return err}
	raw,err:=json.Marshal(marker)
	if err!=nil{return err}
	file,err:=os.OpenFile(filepath.Join(w.pending,"verified.json"),os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600)
	if err!=nil{return err}
	_,writeErr:=file.Write(raw)
	syncErr:=file.Sync()
	closeErr:=file.Close()
	if err:=errors.Join(writeErr,syncErr,closeErr);err!=nil{return err}
	if err=syncReceiverVerifiedDirectory(w.pending);err!=nil{return err}
	if err=os.Rename(w.pending,dest);err!=nil{return err}
	w.pending=""
	return syncReceiverVerifiedDirectory(w.root)
}
func syncReceiverVerifiedDirectory(dir string)error{
	d,err:=os.Open(dir)
	if err!=nil{return err}
	err=errors.Join(d.Sync(),d.Close())
	return err
}

// A cache marker merely binds previously verified data to the immutable
// recorded receipt. It does not authorize SQL publication by itself.
