//go:build !windows

package telemetrybackend
import (
 "os"
 "path/filepath"
 "testing"
 "time"
)
func fixture()Entry{return Entry{Version:1,Host:"c220",RunID:"run",Sequence:1,Stream:"samples",ObservedAt:time.Now().UTC(),Data:map[string]interface{}{"cpu":"observed"}}}
func TestCustodyRoundTripAndTamper(t *testing.T){
 dir:=t.TempDir()
 e:=fixture()
 path,err:=Put(dir,e);if err!=nil{t.Fatal(err)}
 got,err:=ReadPending(dir,5);if err!=nil||len(got)!=1{t.Fatalf("read %v count=%d",err,len(got))}
 if err:=os.WriteFile(path,[]byte("tampered"),0600);err!=nil{t.Fatal(err)}
 if _,err:=ReadPending(dir,5);err==nil{t.Fatal("tampered spool accepted")}
 if err:=os.Remove(path);err!=nil{t.Fatal(err)}
 if _,err:=Put(dir,e);err!=nil{t.Fatal(err)}
 got,err=ReadPending(dir,5);if err!=nil{t.Fatal(err)}
 if err:=Retire(dir,got);err!=nil{t.Fatal(err)}
 got,err=ReadPending(dir,5);if err!=nil||len(got)!=0{t.Fatal("retirement failed")}
}
func TestPrivateBoundary(t *testing.T){
 dir:=t.TempDir()
 if err:=os.Chmod(dir,0755);err!=nil{t.Fatal(err)}
 if _,err:=Put(dir,fixture());err==nil{t.Fatal("world-readable spool accepted")}
}
func TestUntrustedSymlink(t *testing.T){
 dir:=t.TempDir()
 target:=filepath.Join(dir,"target")
 if err:=os.WriteFile(target,[]byte("x"),0600);err!=nil{t.Fatal(err)}
 if err:=os.Symlink(target,filepath.Join(dir,"1_bad.json"));err!=nil{t.Fatal(err)}
 if _,err:=ReadPending(dir,5);err==nil{t.Fatal("symlink accepted")}
}
func TestInvalidObservations(t *testing.T){
 dir:=t.TempDir()
 e:=fixture();e.Stream="other"
 if _,err:=Put(dir,e);err==nil{t.Fatal("invalid stream accepted")}
 e=fixture();e.Data=nil
 if _,err:=Put(dir,e);err==nil{t.Fatal("missing observation status accepted")}
}
