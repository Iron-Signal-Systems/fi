package backendinstall

import (
    "strings"
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
    if strings.Contains(script,"/sbin/umount")||
        strings.Contains(script,"/sbin/mount -a")||
        !strings.Contains(c1RAMHostServiceConfig,"fi_c1_ram_enable=\"NO\""){
        t.Fatal("host C1 RAM runtime must never unmount, blanket-mount, or autoenable")
    }
}
