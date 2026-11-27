package backendinstall

import (
    "os"
    "path/filepath"
    "testing"
)

func TestC1RAMFSTABAuditRecognizesExactAndAbsentEntries(t *testing.T){
    dir:=t.TempDir()
    file:=filepath.Join(dir,"jail.fstab")
    target:="/fast/jails/roots/fi-sor-db/var/run/fi-c1-handoff"
    entry:="/var/run/fi-c1-handoff "+target+" nullfs ro 0 0"
    state,err:=inspectC1RAMFSTAB(file,target,entry)
    if err!=nil||state!=C1FSTABAbsent{
        t.Fatalf("new mount should be absent, got %s %v",state,err)
    }
    if err:=os.WriteFile(file,[]byte("# managed other mount\n/safe /jail/safe nullfs rw 0 0\n"+entry+"\n"),0600);err!=nil{t.Fatal(err)}
    state,err=inspectC1RAMFSTAB(file,target,entry)
    if err!=nil||state!=C1FSTABExact{t.Fatalf("existing exact RO mapping: %s %v",state,err)}
}
func TestC1RAMFSTABAuditFailsClosedOnForeignOrDuplicateMount(t *testing.T){
    dir:=t.TempDir()
    file:=filepath.Join(dir,"jail.fstab")
    target:="/fast/jails/roots/fi-sor-db/var/run/fi-c1-handoff"
    correct:="/var/run/fi-c1-handoff "+target+" nullfs ro 0 0"
    cases:=[]string{
        "/var/run/fi-c1-handoff "+target+" nullfs rw 0 0\n",
        "/tmp/foreign "+target+" nullfs ro 0 0\n",
        correct+"\n"+correct+"\n",
        correct+"\n"+"/tmp/foreign "+target+" nullfs ro 0 0\n",
    }
    for _,value:=range cases{
        if err:=os.WriteFile(file,[]byte(value),0600);err!=nil{t.Fatal(err)}
        if _,err:=inspectC1RAMFSTAB(file,target,correct);err==nil{
            t.Fatalf("foreign/duplicate RAM mapping accepted: %q",value)
        }
    }
    if err:=os.Remove(file);err!=nil{t.Fatal(err)}
    if err:=os.Symlink("/etc/fstab",file);err!=nil{t.Fatal(err)}
    if _,err:=inspectC1RAMFSTAB(file,target,correct);err==nil{
        t.Fatal("symlink host mount policy accepted")
    }
}
