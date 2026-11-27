package backendinstall

import (
    "os"
    "testing"
)
func TestC1RAMMountSecurityRequiresExactFreeBSDOwnerAndFlags(t *testing.T){
    base:=c1FreeBSDNoExec|c1FreeBSDNoSuid
    tests:=[]struct{name string;flags uint64;mode os.FileMode;uid,gid,expectUID,expectGID uint32;good bool}{
        {"exact",base,os.ModeDir|0770,4100,4200,4100,4200,true},
        {"world",base,os.ModeDir|0777,4100,4200,4100,4200,false},
        {"file",base,0770,4100,4200,4100,4200,false},
        {"wrong-uid",base,os.ModeDir|0770,4101,4200,4100,4200,false},
        {"wrong-gid",base,os.ModeDir|0770,4100,4201,4100,4200,false},
        {"missing-noexec",c1FreeBSDNoSuid,os.ModeDir|0770,4100,4200,4100,4200,false},
        {"missing-nosuid",c1FreeBSDNoExec,os.ModeDir|0770,4100,4200,4100,4200,false},
        {"missing-id",base,os.ModeDir|0770,4100,4200,0,4200,false},
    }
    for _,tc:=range tests{
        t.Run(tc.name,func(t *testing.T){
            err:=ValidateC1RAMMountSecurity(tc.flags,tc.mode,
                tc.uid,tc.gid,tc.expectUID,tc.expectGID)
            if (err==nil)!=tc.good{t.Fatalf("tmpfs security acceptance=%t err=%v",tc.good,err)}
        })
    }
}
