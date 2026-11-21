package c1handoff

import (
    "bytes"
    "os"
    "path/filepath"
    "testing"
)
func TestC1SharedRAMRoundTripAndAuthenticatedReference(t *testing.T){
    dir:=t.TempDir()
    if e:=os.Chmod(dir,0700);e!=nil{t.Fatal(e)}
    s,e:=NewRAMStore(dir);if e!=nil{t.Fatal(e)}
    payload:=[]byte("preprocessed C1 material; not a durable journal")
    ref,e:=s.Put(payload,2);if e!=nil{t.Fatal(e)}
    got,e:=s.Get(ref);if e!=nil||!bytes.Equal(got,payload){t.Fatalf("RAM roundtrip %v",e)}
    f:=Frame{Kind:Source,SourceID:"source",GenerationID:"generation",
        ReceiptSHA256:string(bytes.Repeat([]byte("a"),64)),Sequence:2,Shared:ref}
    var wire bytes.Buffer
    if e=WriteFrame(&wire,f);e!=nil{t.Fatal(e)}
    decoded,e:=ReadFrame(&wire)
    if e!=nil||decoded.Shared!=ref||len(decoded.Rows)!=0{t.Fatalf("RAM reference wire %v",e)}
    bad:=ref;bad.SHA256[0]^=1
    if _,e=s.Get(bad);e==nil{t.Fatal("mutated digest accepted")}
    if e=os.WriteFile(filepath.Join(s.root,ref.Name),[]byte("mutated"),0640);e!=nil{t.Fatal(e)}
    if _,e=s.Get(ref);e==nil{t.Fatal("mutated buffer accepted")}
    if e=s.Remove(ref);e!=nil{t.Fatal(e)}
}
func TestC1SharedRAMRejectsPathTraversalAndControlFrame(t *testing.T){
    dir:=t.TempDir()
    if e:=os.Chmod(dir,0700);e!=nil{t.Fatal(e)}
    s,e:=NewRAMStore(dir);if e!=nil{t.Fatal(e)}
    ref,e:=s.Put([]byte("hello"),1);if e!=nil{t.Fatal(e)}
    bad:=ref;bad.Name="../sneak"
    if _,e=s.Get(bad);e==nil{t.Fatal("traversal accepted")}
    ctl:=Frame{Kind:Drain,SourceID:"s",GenerationID:"g",ReceiptSHA256:string(bytes.Repeat([]byte("b"),64)),Sequence:3,Shared:ref}
    if e=ctl.Validate();e==nil{t.Fatal("control frame accepted RAM SQL payload")}
    f:=Frame{Kind:Source,SourceID:"s",GenerationID:"g",ReceiptSHA256:ctl.ReceiptSHA256,Sequence:3,Shared:ref,Rows:[]Row{{}}}
    if e=f.Validate();e==nil{t.Fatal("hybrid inline+RAM accepted")}
    if e=s.Remove(ref);e!=nil{t.Fatal(e)}
}
