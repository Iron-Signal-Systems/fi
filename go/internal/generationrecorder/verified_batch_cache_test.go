// Copyright (c) 2026 John Joseph Wood. All rights reserved.
package generationrecorder

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)
func TestReceiverVerifiedBatchCachePublishesOnlyAfterReceipt(t *testing.T){
	root:=t.TempDir()
	if err:=os.Chmod(root,0700);err!=nil{t.Fatal(err)}
	writer,err:=newReceiverVerifiedBatchWriter(root)
	if err!=nil{t.Fatal(err)}
	body:=[]byte("{\"record\":1}\n")
	manifest:=[]byte("{\"manifest\":1}")
	validate:=func(_ string,r io.Reader)error{
		_,e:=io.Copy(io.Discard,r)
		return e
	}
	if err=writer.Consume("batch-a.jsonl",bytes.NewReader(body),validate);err!=nil{t.Fatal(err)}
	if err=writer.Consume("batch-a.manifest.json",bytes.NewReader(manifest),validate);err!=nil{t.Fatal(err)}
	receipt:=DurableResult{
		ReceiptSHA256:strings.Repeat("a",64),
		Receipt:RecordedReceipt{BatchCount:1,RecordCount:1,
			DataBytes:uint64(len(body)),TransferSHA256:strings.Repeat("b",64)},
	}
	dest:=filepath.Join(root,"receipt-"+receipt.ReceiptSHA256)
	if _,err=os.Stat(dest);!os.IsNotExist(err){t.Fatal("provisional cache published before durable receipt")}
	if err=writer.Publish(receipt);err!=nil{t.Fatal(err)}
	for _,file:=range []string{"batch-00000000.data","batch-00000000.manifest","verified.json"}{
		if _,err=os.Stat(filepath.Join(dest,file));err!=nil{t.Fatal(err)}
	}
	writer.Discard()
	retry,err:=newReceiverVerifiedBatchWriter(root)
	if err!=nil{t.Fatal(err)}
	if err=retry.Consume("batch-a.jsonl",bytes.NewReader(body),validate);err!=nil{t.Fatal(err)}
	if err=retry.Consume("batch-a.manifest.json",bytes.NewReader(manifest),validate);err!=nil{t.Fatal(err)}
	if err=retry.Publish(receipt);err!=nil{t.Fatal(err)}
	retry.Discard()
}

func TestReceiverVerifiedBatchSharedGroupPermissions(t *testing.T) {
	root:=t.TempDir()
	if err:=os.Chmod(root,os.ModeSetgid|0750);err!=nil{t.Fatal(err)}
	writer,err:=newReceiverVerifiedBatchWriter(root)
	if err!=nil{t.Fatal(err)}
	consume:=func(_ string,r io.Reader)error{_,e:=io.Copy(io.Discard,r);return e}
	if err=writer.Consume("batch-a.jsonl",bytes.NewReader([]byte("{\"record\":1}\n")),consume);err!=nil{t.Fatal(err)}
	if err=writer.Consume("batch-a.manifest.json",bytes.NewReader([]byte("{\"manifest\":1}")),consume);err!=nil{t.Fatal(err)}
	result:=DurableResult{ReceiptSHA256:strings.Repeat("a",64),
		Receipt:RecordedReceipt{BatchCount:1,RecordCount:1,DataBytes:13,TransferSHA256:strings.Repeat("b",64)}}
	if err=writer.Publish(result);err!=nil{t.Fatal(err)}
	dest:=filepath.Join(root,"receipt-"+result.ReceiptSHA256)
	info,err:=os.Stat(dest)
	if err!=nil{t.Fatal(err)}
	if info.Mode().Perm()!=0750||info.Mode()&os.ModeSetgid==0{
		t.Fatalf("receiver cache directory lost shared setgid permissions: %v",info.Mode())
	}
	for _,name:=range []string{"batch-00000000.data","batch-00000000.manifest","verified.json"}{
		st,err:=os.Stat(filepath.Join(dest,name))
		if err!=nil{t.Fatal(err)}
		if st.Mode().Perm()!=0640{
			t.Fatalf("receiver shared artifact %s mode=%v want 0640",name,st.Mode())
		}
	}
}
