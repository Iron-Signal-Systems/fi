package recordingest

import (
 "context"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestDeferredArtifactProofFailClosed(t *testing.T){
 root:=t.TempDir()
 d:=BacklogCheckpointDescriptor{
  ReceiptSHA256:strings.Repeat("a",64),
  StartBatch:158,EndBatch:215,
 }
 gen:=filepath.Join(root,"receipt-"+d.ReceiptSHA256)
 if err:=os.Mkdir(gen,0700);err!=nil{t.Fatal(err)}
 pending,err:=os.MkdirTemp(gen,".window-building-deferred-")
 if err!=nil{t.Fatal(err)}
 p:=&deferredBacklogWindow{
  root:root,pending:pending,
  ready:filepath.Join(gen,"window-00000003"),
  descriptor:d,start:158,end:215,
 }
 if err:=p.check(context.Background(),d,3,root);err!=nil{t.Fatal(err)}
 if err:=p.check(context.Background(),d,4,root);err==nil{t.Fatal("wrong window accepted")}
 wrong:=d;wrong.EndBatch++
 if err:=p.check(context.Background(),wrong,3,root);err==nil{t.Fatal("wrong signed descriptor accepted")}
 if err:=p.check(context.Background(),d,3,filepath.Join(root,"other"));err==nil{t.Fatal("wrong private root accepted")}
 p.published=true
 if err:=p.check(context.Background(),d,3,root);err==nil{t.Fatal("published proof reused")}
 p.published=false
 if err:=os.Remove(pending);err!=nil{t.Fatal(err)}
 if err:=p.check(context.Background(),d,3,root);err==nil{t.Fatal("missing pending stage accepted")}
}

func TestPrivateDeferredCloneContextIsOptIn(t *testing.T){
 if privateDeferredCloneEnabled(context.Background()){t.Fatal("default cannot defer artifact validation")}
 ctx:=WithPrivateDeferredVerifiedClone(context.Background())
 if !privateDeferredCloneEnabled(ctx){t.Fatal("explicit test context missing")}
 if deferredWindowFromContext(ctx)!=nil{t.Fatal("unexpected fabricated pending window")}
}

func TestPrivateDeferredFaultRequiresExplicitSupportedMode(t *testing.T) {
 if got:=privateDeferredFault(context.Background());got!="" {t.Fatal("default fault injection must be disabled")}
 if _,err:=WithPrivateDeferredFault(context.Background(),"unknown");err==nil {t.Fatal("arbitrary fault injection accepted")}
 if _,err:=WithPrivateDeferredFault(nil,DeferredFaultCorruptClone);err==nil {t.Fatal("nil context accepted")}
 for _,mode:=range []string{DeferredFaultCorruptClone,DeferredFaultAfterPublish,DeferredFaultKillAfterPublish} {
  ctx,err:=WithPrivateDeferredFault(context.Background(),mode)
  if err!=nil {t.Fatal(err)}
  if got:=privateDeferredFault(ctx);got!=mode {t.Fatalf("requested fault %q became %q",mode,got)}
 }
}
