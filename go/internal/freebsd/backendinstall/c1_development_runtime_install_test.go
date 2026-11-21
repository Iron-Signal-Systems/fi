package backendinstall

import (
    "os"
    "path/filepath"
    "strings"
    "testing"
)

func TestC1DevelopmentRuntimePlanDisabledAndJailBound(t *testing.T){
    ingest,sor:=t.TempDir(),t.TempDir()
    config:=Config{values:map[string]string{
        "FI_INGEST_ROOT":ingest,"FI_SOR_DB_ROOT":sor,"FI_RUNTIME_GID":"4100",
    }}
    plan,err:=buildC1DevelopmentRuntimePlan(config)
    if err!=nil{t.Fatal(err)}
    if len(plan.Files)!=6||len(plan.Parents)!=6{
        t.Fatalf("C1 rc plan count files=%d directories=%d",len(plan.Files),len(plan.Parents))
    }
    lookup:=make(map[string]runtimeFileSpec,len(plan.Files))
    for _,f:=range plan.Files{
        lookup[f.Role]=f
        if !strings.HasPrefix(f.Target,ingest+"/")&&!strings.HasPrefix(f.Target,sor+"/"){
            t.Fatalf("C1 rc escaped jail root: %s",f.Target)
        }
        if f.UID!=0||!containsExactLine(f.Content,runtimeFileMarker){
            t.Fatalf("C1 rc missing root-owned marker: %s",f.Role)
        }
    }
    for _,role:=range []string{"c1-ingest-runtime-config","c1-sor-runtime-config"}{
        f,ok:=lookup[role]
        if !ok||f.GID!=4100||f.Mode!=0640||
            !strings.Contains(string(f.Content),"_enable=\"NO\""){
            t.Fatalf("C1 rc must be root-written but service-readable and disabled: %s",role)
        }
    }
    if !strings.Contains(string(lookup["c1-ingest-rc-service"].Content),"daemon")||
        !strings.Contains(string(lookup["c1-ingest-rc-service"].Content)," -u fi-ingest ")||
        !strings.Contains(string(lookup["c1-sor-rc-service"].Content)," -u fi-sor "){
        t.Fatal("C1 service supervisor runs with incorrect jail identity")
    }
    if strings.Contains(string(lookup["c1-ingest-runner"].Content),"postgres")||
        !strings.Contains(string(lookup["c1-sor-runner"].Content),"-postgres-local"){
        t.Fatal("FI C1 mistakenly gave PostgreSQL responsibility to fi-ingest")
    }
    if got:=lookup["c1-ingest-runner"].Target;got!=filepath.Join(ingest,"usr/local/libexec/fi-c1-ingest-run"){
        t.Fatalf("C1 ingest run script installed at wrong path: %s",got)
    }
    if got:=lookup["c1-sor-runner"].Target;got!=filepath.Join(sor,"usr/local/libexec/fi-c1-sor-run"){
        t.Fatalf("C1 SoR run script installed at wrong path: %s",got)
    }
}
func TestC1DevelopmentRuntimeRejectsSameJailAndSymlink(t *testing.T){
    ingest:=t.TempDir()
    cfg:=Config{values:map[string]string{
        "FI_INGEST_ROOT":ingest,"FI_SOR_DB_ROOT":ingest,"FI_RUNTIME_GID":"4100",
    }}
    if _,err:=buildC1DevelopmentRuntimePlan(cfg);err==nil{
        t.Fatal("C1 rc co-located fi-ingest and fi-sor")
    }
    target:=filepath.Join(t.TempDir(),"alias")
    if err:=os.Symlink(ingest,target);err!=nil{t.Fatal(err)}
    cfg.values["FI_SOR_DB_ROOT"]=target
    if _,err:=buildC1DevelopmentRuntimePlan(cfg);err==nil{
        t.Fatal("C1 rc accepted a symlinked SoR jail")
    }
}
