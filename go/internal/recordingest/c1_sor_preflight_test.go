//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Installed fi-sor startup and read-only --preflight must use the SAME
// configuration gate. Invalid jail, TLS, or PostgreSQL identities may not
// open a handoff listener, spawn B or touch the canonical database.
package recordingest

import (
    "context"
    "strings"
    "testing"
)

func TestC1SoRPreflightRejectsInvalidJailAndSQLBeforeNetwork(t *testing.T) {
    baseline:=C1SoRServerConfig{
        Bind:"172.20.10.12:8443",
        LocalPostgresDSN:"host=/var/db/fi/sor/run port=5432 dbname=fi user=fi_ingest",
        PublisherPostgresDSN:"host=/var/db/fi/sor/run port=5432 dbname=fi user=fi_c1_publisher",
        SharedRAMDir:"/var/run/fi-c1-handoff",
        CustodyRoot:"/var/db/fi/custody/generation",
        RecordedRoot:"/var/db/fi/custody/recorded",
        SQLWorkersMax:2,
    }
    cases:=[]struct{name string; change func(*C1SoRServerConfig)}{
        {"no-private-bind",func(c *C1SoRServerConfig){c.Bind=""}},
        {"loopback-bind",func(c *C1SoRServerConfig){c.Bind="127.0.0.1:8443"}},
        {"nil-sql-worker",func(c *C1SoRServerConfig){c.LocalPostgresDSN=""}},
        {"nil-publisher",func(c *C1SoRServerConfig){c.PublisherPostgresDSN=""}},
        {"missing-receiver-custody",func(c *C1SoRServerConfig){c.CustodyRoot=""}},
        {"missing-receiver-receipts",func(c *C1SoRServerConfig){c.RecordedRoot=""}},
        {"missing-shared-tmpfs",func(c *C1SoRServerConfig){c.SharedRAMDir=""}},
        {"zero-sql-workers",func(c *C1SoRServerConfig){c.SQLWorkersMax=0}},
        {"excess-sql-workers",func(c *C1SoRServerConfig){c.SQLWorkersMax=33}},
        {"remote-postgresql",func(c *C1SoRServerConfig){
            c.LocalPostgresDSN="host=192.168.20.1 port=5432 dbname=fi user=fi_ingest"
        }},
        {"publisher-uses-ingest-role",func(c *C1SoRServerConfig){
            c.PublisherPostgresDSN=c.LocalPostgresDSN
        }},
    }
    for _,tc:=range cases{
        t.Run(tc.name,func(t *testing.T){
            cfg:=baseline
            tc.change(&cfg)
            if err:=PreflightC1SoRWorker(context.Background(),cfg);err==nil{
                t.Fatal("C1 SoR read-only startup admitted invalid or unsafe jail config")
            }
        })
    }
    if err:=PreflightC1SoRWorker(nil,baseline);err==nil||
        !strings.Contains(err.Error(),"context"){
        t.Fatalf("C1 preflight accepted nil service context: %v",err)
    }
}
