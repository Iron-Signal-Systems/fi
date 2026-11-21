// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import "testing"

func TestC1SoRBackendBoundary(t *testing.T) {
    good := C1SoRBackendIdentity{
        Database:"fi", Role:"fi_ingest", ServerAddress:"172.20.23.33",
        ClientAddress:"172.20.23.32", BackendPID:12345,
    }
    if err:=ValidateC1SoRBackendIdentity("172.20.23.33",good); err!=nil {
        t.Fatalf("pinned remote fi-sor backend rejected: %v",err)
    }
    tests:=[]struct{
        name string
        expected string
        mutate func(*C1SoRBackendIdentity)
    }{
        {"missing-pin","",func(*C1SoRBackendIdentity){}},
        {"loopback-pin","127.0.0.1",func(*C1SoRBackendIdentity){}},
        {"wrong-server","172.20.23.34",func(*C1SoRBackendIdentity){}},
        {"local-unix-socket","172.20.23.33",func(v *C1SoRBackendIdentity){v.ClientAddress=""}},
        {"wrong-database","172.20.23.33",func(v *C1SoRBackendIdentity){v.Database="fi_telemetry"}},
        {"wrong-role","172.20.23.33",func(v *C1SoRBackendIdentity){v.Role="postgres"}},
        {"standby","172.20.23.33",func(v *C1SoRBackendIdentity){v.InRecovery=true}},
        {"missing-backend-pid","172.20.23.33",func(v *C1SoRBackendIdentity){v.BackendPID=0}},
        {"wrong-backend-ip","172.20.23.33",func(v *C1SoRBackendIdentity){v.ServerAddress="172.20.23.34"}},
    }
    for _,tc:=range tests {
        t.Run(tc.name,func(t *testing.T){
            got:=good
            tc.mutate(&got)
            if err:=ValidateC1SoRBackendIdentity(tc.expected,got);err==nil {
                t.Fatalf("C1 accepted unsafe backend: %+v",got)
            }
        })
    }
}
