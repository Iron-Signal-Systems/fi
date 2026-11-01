// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
    "context"
    "strings"
    "testing"

    "github.com/jackc/pgx/v5"
)

func TestPrivateProjectionSQLRewritePreservesLiteralsAndComments(t *testing.T) {
    q:=`INSERT INTO fi.windows_security_event (source_record_id,computer)
SELECT source_record_id, 'literal fi.source_record' FROM fi.source_record
-- fi.do_not_touch in comments
WHERE scope_id=$1 /* fi.still_comment */`
    got,err:=rewritePrivateProjectionStatement(q)
    if err!=nil{t.Fatal(err)}
    for _,part:=range []string{
        "INSERT INTO fi_recovery_projection.windows_security_event",
        "FROM fi_recovery_projection.source_record",
        "'literal fi.source_record'",
        "-- fi.do_not_touch in comments",
        "/* fi.still_comment */",
    }{
        if !strings.Contains(got,part){t.Fatalf("expected SQL part %q absent from %q",part,got)}
    }
}

func TestPrivateProjectionSQLRewriteFailsClosed(t *testing.T){
    bad:=[]string{
        "",
        "SELECT 1",
        "SELECT 'fi.source_record'",
        "UPDATE fi.source_record SET scope_id='altered'",
        "DELETE FROM fi.source_record",
        "DROP TABLE fi.source_record",
        "INSERT INTO fi.source_record VALUES (1); DROP TABLE fi.recorded_generation",
        "INSERT INTO fi_recovery_projection.source_record VALUES (1)",
        "SELECT * FROM fi.source_record WHERE s='unclosed",
        "SELECT * FROM fi.source_record /* unclosed",
        "SELECT $$fi.source_record$$ FROM fi.source_record",
        "SELECT * FROM public.source_record",
    }
    for _,q:=range bad{
        if _,err:=rewritePrivateProjectionStatement(q);err==nil{
            t.Fatalf("unsafe SQL unexpectedly accepted: %q",q)
        }
    }
    cases:=[]struct{input,contains string}{
        {"SELECT\n count(*) FROM fi.source_record","fi_recovery_projection.source_record"},
        {"INSERT INTO fi.source_record(id) VALUES($1)","fi_recovery_projection.source_record"},
        {"WITH x AS (SELECT 1) SELECT * FROM fi.source_record","fi_recovery_projection.source_record"},
    }
    for _,tc:=range cases{
        got,err:=rewritePrivateProjectionStatement(tc.input)
        if err!=nil||!strings.Contains(got,tc.contains){
            t.Fatalf("valid SQL rejected or mangled: %q => %q err=%v",tc.input,got,err)
        }
    }
}

func TestPrivateProjectionTxRejectsSQLBypass(t *testing.T){
    var tx privateProjectionTx
    if tx.Conn()!=nil{t.Fatal("private projector exposed raw connection")}
    if _,err:=tx.Begin(context.Background());err==nil{t.Fatal("nested transaction allowed")}
    if _,err:=tx.Prepare(context.Background(),"s","SELECT 1");err==nil{
        t.Fatal("prepared query allowed")
    }
    if _,err:=tx.CopyFrom(context.Background(),pgx.Identifier{"fi",""},nil,nil);err==nil{
        t.Fatal("unsafe COPY target allowed")
    }
    if _,err:=tx.Exec(context.Background(),"UPDATE fi.source_record SET scope_id='changed'");err==nil{
        t.Fatal("direct UPDATE passed to transaction")
    }
    if err:=tx.QueryRow(context.Background(),"SELECT 1").Scan();err==nil{
        t.Fatal("unqualified QueryRow passed to transaction")
    }
    if err:=tx.SendBatch(context.Background(),nil).Close();err==nil{
        t.Fatal("unverified SendBatch passed to transaction")
    }
}
