//go:build fi_c1_sor_dev
package recordingest

import (
    "os"
    "path/filepath"
    "strings"
    "testing"
)

func TestC1SoRCloneGateRejectsLiveAndUnrelatedPaths(t *testing.T){
    for _,root:=range []string{
        "/var/db/fi/sor/postgres",
        "/var/db/fi/sor",
        "/var/tmp",
        "/var/tmp/fi-c1-sor-bench.123",
        "/var/tmp/fi-c1-sor-bench.test/../../var/db/fi/sor/postgres",
        "/var/tmp/fi-c1-sor-bench.valid123/../fi-c1-sor-bench.other",
        "/var/tmp/fi-c1-sor-bench.valid123/pgdata",
        "var/tmp/fi-c1-sor-bench.valid123",
    }{
        if err:=c1ValidateIsolatedBenchmarkRoot(root);err==nil{
            t.Fatalf("unsafe clone root accepted: %s",root)
        }
    }
}
func TestC1SoRCloneGateAcceptsOnlyFreshPhysicalDirectories(t *testing.T){
    // A strictly bounded fixture is in the permitted /var/tmp namespace
    // and is never a PostgreSQL database or signed custody.
    root,err:=os.MkdirTemp("/var/tmp","fi-c1-sor-bench.")
    if err!=nil{t.Skipf("cannot allocate isolated /var/tmp fixture: %v",err)}
    defer os.RemoveAll(root)
    for _,part:=range []string{"pgdata","socket"}{
        if err=os.Mkdir(filepath.Join(root,part),0700);err!=nil{t.Fatal(err)}
    }
    if err:=c1ValidateIsolatedBenchmarkRoot(root);err!=nil{t.Fatal(err)}
    if err=os.Remove(filepath.Join(root,"socket"));err!=nil{t.Fatal(err)}
    if err=os.Symlink("/var/tmp",filepath.Join(root,"socket"));err!=nil{t.Fatal(err)}
    if err:=c1ValidateIsolatedBenchmarkRoot(root);err==nil||
       !strings.Contains(err.Error(),"symlinked"){
        t.Fatalf("symlinked clone socket not refused: %v",err)
    }
}
