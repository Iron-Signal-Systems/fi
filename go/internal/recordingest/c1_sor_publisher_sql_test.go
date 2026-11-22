//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
    "strings"
    "testing"
)

func TestC1PublisherRoleIsNotIngestWorkerOrRemoteDatabase(t *testing.T){
    for _,dsn:=range []string{
        "",
        "host=127.0.0.1 port=5432 dbname=fi user=fi_c1_publisher sslmode=disable",
        "host=/var/run/postgresql port=5432 dbname=fi user=fi_ingest",
        "host=/var/run/postgresql port=5432 dbname=postgres user=fi_c1_publisher",
        "host=/tmp/../var/run/postgresql port=5432 dbname=fi user=fi_c1_publisher",
    }{
        if _,err:=c1SoRLocalPublisherConfig(dsn);err==nil{
            t.Fatalf("C1 canonical publisher admitted inappropriate SQL connection: %q",dsn)
        }
    }
    cfg,err:=c1SoRLocalPublisherConfig(
        "host=/var/run/postgresql port=5432 dbname=fi user=fi_c1_publisher")
    if err!=nil||cfg.User!=c1PublisherRole||cfg.Database!="fi"{
        t.Fatalf("separate fi-sor local SQL publication disabled: %v",err)
    }
}

func TestC1PublisherRolePlanDoesNotIncreaseIngestWorkerAuthority(t *testing.T){
    statements:=C1CanonicalPublisherRolePlan()
    if len(statements)<6{t.Fatal("incomplete separate publication role plan")}
    for _,ddl:=range statements{
        if strings.Contains(ddl,"TO fi_ingest")||
            strings.Contains(ddl,"TRUNCATE")||
            strings.Contains(ddl,"DELETE")||
            strings.Contains(ddl,"UPDATE")||
            strings.Contains(ddl,"SUPERUSER")&&!strings.Contains(ddl,"NOSUPERUSER"){
            t.Fatalf("C1 canonical publisher plan grants unsafe authority: %s",ddl)
        }
    }
    if !strings.Contains(strings.Join(statements,"\n"),
        "GRANT SELECT,INSERT,MAINTAIN ON ALL TABLES IN SCHEMA fi TO fi_c1_publisher"){
        t.Fatal("C1 canonical publisher lacks lock permission on populated FI schema")
    }
}
