//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Receiver-published verified batch source (read-only inside fi-sor). The
// receiver publishes this after authenticating the whole FIGT and recording
// the immutable receipt. The live SoR NEVER treats the cache as an Accepted
// authority; independent B reopens the original FIGT and checks canonical SQL.
package recordingest

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func c1ReceiverCachePrivateRoot(root string)error{
	if !filepath.IsAbs(root)||filepath.Clean(root)!=root{
		return errors.New("FI receiver cache: absolute clean root required")
	}
	st,err:=os.Lstat(root)
	if err!=nil{return err}
	if !st.IsDir()||st.Mode()&os.ModeSymlink!=0||
		(st.Mode().Perm()!=0700 && st.Mode().Perm()!=0750){
		return fmt.Errorf("FI receiver cache: private root must be 0700 or 0750: %s",root)
	}
	return nil
}
func c1ReadReceiverVerifiedCacheFile(path string,maximum int64)([]byte,error){
	if maximum<=0{return nil,errors.New("FI receiver cache: invalid bounded read")}
	st,err:=os.Lstat(path)
	if err!=nil{return nil,err}
	if !st.Mode().IsRegular() ||
		(st.Mode().Perm()!=0600&&st.Mode().Perm()!=0640)||
		st.Size()<1||st.Size()>maximum{
		return nil,fmt.Errorf("FI receiver cache: invalid private artifact %s",path)
	}
	file,err:=os.Open(path)
	if err!=nil{return nil,err}
	opened,err:=file.Stat()
	if err!=nil{_ =file.Close();return nil,err}
	if !os.SameFile(st,opened){_ =file.Close();return nil,errors.New("FI receiver cache: file changed while opening")}
	b,readErr:=io.ReadAll(io.LimitReader(file,maximum+1))
	closeErr:=file.Close()
	if err=errors.Join(readErr,closeErr);err!=nil{return nil,err}
	if int64(len(b))!=st.Size(){return nil,errors.New("FI receiver cache: file size changed")}
	return b,nil
}
func c1ReceiverVerifiedCacheOpen(root,receiptSHA,transferSHA string,batches,records,bytes uint64)(string,error){
	if err:=c1ReceiverCachePrivateRoot(root);err!=nil{return "",err}
	dir:=filepath.Join(root,"receipt-"+receiptSHA)
	if err:=c1ReceiverCachePrivateRoot(dir);err!=nil{return "",err}
	raw,err:=c1ReadReceiverVerifiedCacheFile(filepath.Join(dir,"verified.json"),4096)
	if err!=nil{return "",err}
	var marker backlogVerifiedCacheMarker
	if err=json.Unmarshal(raw,&marker);err!=nil{return "",err}
	if marker.ReceiptSHA256!=receiptSHA||marker.TransferSHA256!=transferSHA||
		marker.BatchCount!=batches||marker.RecordCount!=records||marker.DataBytes!=bytes{
		return "",errors.New("FI receiver cache: receipt/transfer-authenticated checkpoint mismatch")
	}
	return dir,nil
}
