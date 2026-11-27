package backendinstall

import (
    "os"
    "path/filepath"
    "strings"
    "testing"
)
func TestC1RAMMountPlanPreservesJailsAndVolatileHandoff(t *testing.T){
    ingest,sor:=t.TempDir(),t.TempDir()
    cfg:=Config{values:map[string]string{
        "FI_RUNTIME_UID":"4100","FI_RUNTIME_GID":"4100",
        "FI_INGEST_ROOT":ingest,"FI_SOR_DB_ROOT":sor,
        "FI_INGEST_FSTAB":"/etc/fstab.fi-ingest",
        "FI_SOR_DB_FSTAB":"/etc/fstab.fi-sor-db",
    }}
    plan,err:=RenderC1RAMMountPlan(cfg)
    if err!=nil{t.Fatal(err)}
    if plan.IngestMount!=filepath.Join(ingest,"var/run/fi-c1-handoff")||
        plan.SoRMount!=filepath.Join(sor,"var/run/fi-c1-handoff")||
        plan.BytesCeiling!=4<<30{
        t.Fatalf("incorrect real jail mountpoint/ceiling: %+v",plan)
    }
    for _,check:=range []string{"tmpfs","noauto","nosuid","noexec",
        "size=4g","uid=4100","gid=4100","mode=0770"}{
        if !strings.Contains(plan.HostFSTABEntry,check){
            t.Fatalf("C1 host RAM must be an explicitly mounted bounded tmpfs: %s missing %s",
                plan.HostFSTABEntry,check)
        }
    }
    if !strings.Contains(plan.IngestEntry," nullfs rw 0 0")||
        !strings.Contains(plan.SoREntry," nullfs ro 0 0")||
        plan.HostRoot!="/var/run/fi-c1-handoff"{
        t.Fatal("unsafe/incorrect C1 two-jail RW producer / RO consumer plan")
    }
}
func TestC1RAMMountPlanRejectsForeignRootsAndCollidingFSTAB(t *testing.T){
    ingest,sor:=t.TempDir(),t.TempDir()
    cfg:=Config{values:map[string]string{
        "FI_RUNTIME_UID":"4100","FI_RUNTIME_GID":"4100",
        "FI_INGEST_ROOT":ingest,"FI_SOR_DB_ROOT":sor,
        "FI_INGEST_FSTAB":"/etc/fstab.fi-ingest",
        "FI_SOR_DB_FSTAB":"/etc/fstab.fi-sor-db",
    }}
    cases:=[]struct{key,value string}{
        {"FI_SOR_DB_ROOT",ingest},
        {"FI_SOR_DB_FSTAB","/etc/fstab.fi-ingest"},
        {"FI_RUNTIME_UID","0"},
        {"FI_RUNTIME_GID","0"},
        {"FI_INGEST_FSTAB","relative/fstab"},
    }
    for _,c:=range cases{
        before:=cfg.values[c.key];cfg.values[c.key]=c.value
        if _,err:=RenderC1RAMMountPlan(cfg);err==nil{
            t.Fatalf("accepted unsafe C1 RAM mount plan %s=%q",c.key,c.value)
        }
        cfg.values[c.key]=before
    }
    alias:=filepath.Join(t.TempDir(),"sor-alias")
    if err:=os.Symlink(sor,alias);err!=nil{t.Fatal(err)}
    cfg.values["FI_SOR_DB_ROOT"]=alias
    if _,err:=RenderC1RAMMountPlan(cfg);err==nil{
        t.Fatal("symlink jail root accepted")
    }
}
