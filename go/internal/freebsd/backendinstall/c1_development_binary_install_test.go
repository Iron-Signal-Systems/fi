package backendinstall

import (
    "os"
    "path/filepath"
    "testing"
)

func TestC1DevelopmentBinariesUseExactSeparateJailRoots(t *testing.T){
    release:=t.TempDir()
    for _,name:=range []string{"fi-c1-ingest-worker","fi-c1-sor-worker","fi-c1-host-preflight"}{
        if err:=os.WriteFile(filepath.Join(release,name),[]byte(name+"-development"),0755);err!=nil{t.Fatal(err)}
    }
    ingest:=t.TempDir()
    sor:=t.TempDir()
    cfg:=Config{values:map[string]string{"FI_INGEST_ROOT":ingest,"FI_SOR_DB_ROOT":sor}}
    plan,err:=buildC1DevelopmentBinaryPlan(cfg,release)
    if err!=nil{t.Fatal(err)}
    if len(plan.Files)!=3||len(plan.Parents)!=3{
        t.Fatal("missing distinct C1 development services")
    }
    if plan.Files[0].Target!=filepath.Join(ingest,"usr/local/sbin/fi-c1-ingest-worker")||
        plan.Files[1].Target!=filepath.Join(sor,"usr/local/sbin/fi-c1-sor-worker")||
        plan.Files[2].Target!="/usr/local/sbin/fi-c1-host-preflight"{
        t.Fatal("C1 binaries escaped their designated jail roots")
    }
    for _,file:=range plan.Files{
        if file.Mode!=0555||file.UID!=0||file.GID!=0{
            t.Fatal("C1 development executable lacks root-owned read-only execute policy")
        }
    }
    if len(plan.Files[0].Content)==0||len(plan.Files[1].Content)==0||
        len(plan.Files[2].Content)==0{
        t.Fatal("missing actual FreeBSD service executables")
    }
}
func TestC1DevelopmentBinaryInstallerRejectsIncompleteOrCollidingPlan(t *testing.T){
    release:=t.TempDir()
    if err:=os.WriteFile(filepath.Join(release,"fi-c1-ingest-worker"),[]byte("ingest"),0755);err!=nil{t.Fatal(err)}
    ingest:=t.TempDir()
    sor:=t.TempDir()
    cfg:=Config{values:map[string]string{"FI_INGEST_ROOT":ingest,"FI_SOR_DB_ROOT":sor}}
    if _,err:=buildC1DevelopmentBinaryPlan(cfg,release);err==nil{
        t.Fatal("incomplete release binaries accepted")
    }
    if err:=os.WriteFile(filepath.Join(release,"fi-c1-sor-worker"),[]byte("sor"),0755);err!=nil{t.Fatal(err)}
    if _,err:=buildC1DevelopmentBinaryPlan(cfg,release);err==nil{
        t.Fatal("missing exact native FreeBSD host preflight executable accepted")
    }
    if err:=os.WriteFile(filepath.Join(release,"fi-c1-host-preflight"),[]byte("host-readonly"),0755);err!=nil{t.Fatal(err)}
    cfg.values["FI_SOR_DB_ROOT"]=ingest
    if _,err:=buildC1DevelopmentBinaryPlan(cfg,release);err==nil{
        t.Fatal("both development workers assigned same jail")
    }
    cfg.values["FI_SOR_DB_ROOT"]=sor
    if err:=os.Remove(filepath.Join(release,"fi-c1-sor-worker"));err!=nil{t.Fatal(err)}
    if err:=os.Symlink("fi-c1-ingest-worker",filepath.Join(release,"fi-c1-sor-worker"));err!=nil{t.Fatal(err)}
    if _,err:=buildC1DevelopmentBinaryPlan(cfg,release);err==nil{
        t.Fatal("symlinked development executable accepted")
    }
}
