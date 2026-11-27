//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
    "context"
    "strings"
    "testing"
)

func TestC1GovernedAdminInstallRequiresExplicitLocalAdministrator(t *testing.T){
    if err:=InstallC1GovernedPendingOnExistingSoR(nil,nil);err==nil{
        t.Fatal("C1 governed SQL role installer accepted missing authority and context")
    }
    if err:=InstallC1GovernedPendingOnExistingSoR(context.Background(),nil);err==nil{
        t.Fatal("C1 governed installer accepted missing local administrator")
    }
}

func TestC1GovernedPublisherInstallPlanCannotRewriteCanonicalHistory(t *testing.T){
    steps:=C1CanonicalPublisherRolePlan()
    if len(steps)<8{t.Fatal("C1 publisher role install plan is incomplete")}
    combined:=strings.Join(steps,"\n")
    required:=[]string{
        "CREATE ROLE fi_c1_publisher LOGIN NOSUPERUSER",
        "GRANT SELECT,INSERT,MAINTAIN ON ALL TABLES IN SCHEMA fi TO fi_c1_publisher",
        "GRANT SELECT,MAINTAIN,TRUNCATE ON ALL TABLES IN SCHEMA fi_c1_pending TO fi_c1_publisher",
    }
    for _,q:=range required{
        if !strings.Contains(combined,q){
            t.Fatalf("C1 offline publisher plan missing restricted role grant %q",q)
        }
    }
    for _,q:=range []string{
        "GRANT UPDATE ON ALL TABLES IN SCHEMA fi",
        "GRANT TRUNCATE ON ALL TABLES IN SCHEMA fi",
        "DELETE FROM fi.", "DROP TABLE fi.","DROP SCHEMA fi.",
        "CREATE DATABASE", "SUPERUSER CREATEDB",
    }{
        if strings.Contains(combined,q){
            t.Fatalf("C1 governed offline SQL role grant contains unsafe canonical operation: %q",q)
        }
    }
}
