//go:build fi_c1_sor_dev

package recordingest

import (
    "strings"
    "testing"
)

func TestC1PrivateSchemaPlanOnlyExactPrivateMigrations(t *testing.T){
    plan,err:=C1PrivateSchemaPlan()
    if err!=nil{t.Fatal(err)}
    if len(plan)!=6{t.Fatalf("expected five canonical migrations and recovery ledger, got %d",len(plan))}
    if plan[0].Name!="0001_relational.sql"||
        plan[4].Name!="0005_usn_capture_binding.sql"||
        plan[5].Name!="fi_recovery_private_ledger"{
        t.Fatal("native private schemas lost exact five FI DDL source order")
    }
    for _,item:=range plan{
        // Audit executable SQL, not explanatory "--" migration comments.
        // The frozen, SHA-pinned source files must retain their comments;
        // removing a comment must not alter the installer SQL itself.
        var executable strings.Builder
        for _,line:=range strings.Split(item.SQL,"\n"){
            if i:=strings.Index(line,"--");i>=0{
                line=line[:i]
            }
            executable.WriteString(line)
            executable.WriteByte('\n')
        }
        sql:=executable.String()
        if item.SQL==""||
            strings.Contains(sql,"fi.source_record")||
            strings.Contains(sql,"CREATE TABLE fi.")||
            strings.Contains(sql,"DROP INDEX CONCURRENTLY")||
            strings.Contains(sql,"\nBEGIN;\n")||
            strings.Contains(sql,"\nCOMMIT;\n"){
            t.Fatalf("unsafe or non-atomic executable private SQL migration: %s",item.Name)
        }
    }
    if !strings.Contains(plan[0].SQL,
        "CREATE SCHEMA fi_recovery_projection AUTHORIZATION fi_owner")||
        !strings.Contains(plan[5].SQL,"CREATE TABLE fi_recovery.typed_window")||
        !strings.Contains(plan[4].SQL,"fi_recovery_projection.usn_read_boundary"){
        t.Fatal("C1 private schema lacks original FI relational, USN or recovery tables")
    }
}
func TestC1PrivateSchemaRejectsUnsafeTransactionEnvelope(t *testing.T){
    for _,sql:=range []string{
        "BEGIN;","\nBEGIN;\nSELECT 1;\n",
        "\nCOMMIT;\n","\nBEGIN;\nBEGIN;\nCOMMIT;\n",
        "\nBEGIN;\nCOMMIT;\nCOMMIT;\n",
    }{
        if _,err:=c1MigrationWithoutTransactionEnvelope(sql);err==nil{
            t.Fatalf("unbalanced or repeated transaction wrapper accepted: %q",sql)
        }
    }
}
