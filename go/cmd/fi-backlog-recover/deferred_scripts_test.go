package main

import (
 "os/exec"
 "path/filepath"
 "testing"
)

// Keep the two host/jail acceptance scripts shell-syntax checked as part
// of ordinary Go CI. They operate on real signed data only when explicitly
// invoked by an operator on the isolated FreeBSD host.
func TestDeferredCloneAcceptanceShellSyntax(t *testing.T) {
 sh,err:=exec.LookPath("sh")
 if err!=nil {t.Skip("sh not present on this CI host")}
 for _,name:=range []string{
  "deferred_clone_provision_jail.sh",
  "run_deferred_clone_k32_10m_host.sh",
  "run_deferred_clone_failure_restart_host.sh",
 } {
  t.Run(name,func(t *testing.T){
   path,err:=filepath.Abs(name)
   if err!=nil {t.Fatal(err)}
   command:=exec.Command(sh,"-n",path)
   if data,err:=command.CombinedOutput();err!=nil {
    t.Fatalf("invalid POSIX shell syntax: %v\n%s",err,data)
   }
  })
 }
}
