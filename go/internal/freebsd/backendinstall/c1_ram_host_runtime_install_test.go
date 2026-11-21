package backendinstall

import (
    "strings"
    "os"
    "os/exec"
    "testing"
)

func TestC1RAMHostRuntimeBootOrderingAndDisabledDefault(t *testing.T){
    script:=renderC1RAMHostRC(4100,4200)
    for _,required:=range []string{
        "# PROVIDE: fi_c1_ram","# REQUIRE: FILESYSTEMS",
        "# BEFORE: jail","/sbin/mount \"$root\"",
        "install -d -o 4100 -g 4200 -m 0770",
        "fi_c1_ram_enable","start_cmd=\"fi_c1_ram_start\"",
    }{
        if !strings.Contains(script,required){
            t.Fatalf("host boot mounting contract missing %q",required)
        }
    }
    if strings.Index(script,"/sbin/mount -p")>
       strings.Index(script,"/usr/bin/install -d -o")||
       !strings.Contains(script,"/bin/ls -A")||
       !strings.Contains(script,"host mountpoint is not empty"){
        t.Fatal("host startup would overwrite an existing mounted filesystem or nonempty directory")
    }
    if strings.Contains(script,"/sbin/umount")||
        strings.Contains(script,"/sbin/mount -a")||
        !strings.Contains(c1RAMHostServiceConfig,"fi_c1_ram_enable=\"NO\""){
        t.Fatal("host C1 RAM runtime must never unmount, blanket-mount, or autoenable")
    }
}

func TestC1RAMHostBootScriptPOSIXShellParse(t *testing.T){
    cmd:=exec.Command("sh","-n")
    cmd.Stdin=strings.NewReader(renderC1RAMHostRC(4100,4200))
    if output,err:=cmd.CombinedOutput();err!=nil{
        t.Fatalf("C1 host rc startup script has invalid POSIX sh syntax: %v %s",err,output)
    }
}
func TestC1RAMHostRuntimePlanNeverEnablesOrMountsOnInstall(t *testing.T){
    ingest,sor:=t.TempDir(),t.TempDir()
    cfg:=Config{values:map[string]string{
        "FI_INGEST_ROOT":ingest,"FI_SOR_DB_ROOT":sor,
        "FI_INGEST_FSTAB":"/etc/jail.fstab.d/fi-ingest",
        "FI_SOR_DB_FSTAB":"/etc/jail.fstab.d/fi-sor",
        "FI_RUNTIME_UID":"4100","FI_RUNTIME_GID":"4200",
    }}
    plan,err:=buildC1RAMHostRuntimePlan(cfg)
    if err!=nil{t.Fatal(err)}
    if len(plan.Files)!=2||len(plan.Parents)!=2{
        t.Fatalf("C1 host RC plan incomplete: files=%d parents=%d",len(plan.Files),len(plan.Parents))
    }
    if plan.Files[0].Target!="/usr/local/etc/rc.d/fi_c1_ram"||
        plan.Files[1].Target!="/etc/rc.conf.d/fi_c1_ram"||
        plan.Files[0].Mode!=0555||plan.Files[1].Mode!=0644{
        t.Fatalf("C1 host startup installed into wrong host service locations: %+v",plan.Files)
    }
    if !strings.Contains(string(plan.Files[0].Content),"install -d -o 4100 -g 4200")||
       !strings.Contains(string(plan.Files[1].Content),"fi_c1_ram_enable=\"NO\""){
        t.Fatal("C1 host tmpfs startup contains wrong UID/GID or enables without acceptance")
    }
    if _,err:=os.Stat("/nonexistent-C1-acceptance-file");err==nil{
        t.Fatal("unexpected host fixture file collision")
    }
}
