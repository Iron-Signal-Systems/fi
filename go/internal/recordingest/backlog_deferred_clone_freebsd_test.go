//go:build freebsd

package recordingest

import (
 "bytes"
 "crypto/sha256"
 "os"
 "path/filepath"
 "testing"
)

// This test is expected to PASS on the user's FreeBSD 15.1/ZFS setup.
// It requires a true CoW clone and proves the two files are independent.
func TestDeferredCloneFreeBSDIndependentBytes(t *testing.T){
 root:=t.TempDir()
 src:=filepath.Join(root,"source.data")
 dst:=filepath.Join(root,"cloned.data")
 original:=bytes.Repeat([]byte("FI signed immutable bytes | 2026\n"),8192)
 if err:=os.WriteFile(src,original,0600);err!=nil{t.Fatal(err)}
 f,err:=os.OpenFile(src,os.O_RDONLY,0)
 if err!=nil{t.Fatal(err)}
 if err=f.Sync();err!=nil{t.Fatal(err)}
 if err=f.Close();err!=nil{t.Fatal(err)}
 if err=cloneDeferredDataFile(src,dst,int64(len(original)));err!=nil{t.Fatalf("ZFS clone-required syscall: %v",err)}
 a,err:=deferredFileStat(src);if err!=nil{t.Fatal(err)}
 b,err:=deferredFileStat(dst);if err!=nil{t.Fatal(err)}
 if a.ino==b.ino||a.dev!=b.dev||a.size!=b.size{t.Fatal("clone aliases source or wrong length")}
 snapshot,err:=os.ReadFile(dst);if err!=nil{t.Fatal(err)}
 if sha256.Sum256(snapshot)!=sha256.Sum256(original){t.Fatal("clone changed signed byte identity")}
 out,err:=os.OpenFile(dst,os.O_WRONLY,0);if err!=nil{t.Fatal(err)}
 if _,err=out.WriteAt([]byte("X"),0);err!=nil{t.Fatal(err)}
 if err=out.Sync();err!=nil{t.Fatal(err)}
 if err=out.Close();err!=nil{t.Fatal(err)}
 untouched,err:=os.ReadFile(src);if err!=nil{t.Fatal(err)}
 if !bytes.Equal(original,untouched){t.Fatal("ZFS clone modified original signed source")}
}
