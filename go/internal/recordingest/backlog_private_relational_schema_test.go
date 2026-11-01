// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
    "os"
    "path/filepath"
    "strings"
    "testing"
)

func TestPrivateProjectionMigrationMirrorsAllFiveRelationalSources(t *testing.T) {
    names:=[]string{
        "0001_relational.sql",
        "0002_source_families.sql",
        "0003_usn_relational_identity.sql",
        "0004_security_field_name_index.sql",
        "0005_usn_capture_binding.sql",
    }
    for _,name:=range names{
        t.Run(name,func(t *testing.T){
            path:=filepath.Join("..","..","..","database","schema",name)
            raw,err:=os.ReadFile(path)
            if err!=nil{t.Fatal(err)}
            original:=string(raw)
            rewritten,err:=RewritePrivateProjectionMigration(name,original)
            if err!=nil{t.Fatal(err)}
            if !strings.Contains(rewritten,"fi_recovery_projection.") {
                t.Fatal("no private schema references after rewrite")
            }
            if strings.Contains(rewritten,"ON fi.") ||
                strings.Contains(rewritten,"REFERENCES fi.") ||
                strings.Contains(rewritten,"INSERT INTO fi.") ||
                strings.Contains(rewritten,"ALTER TABLE fi.") ||
                strings.Contains(rewritten,"DROP INDEX IF EXISTS fi.") ||
                strings.Contains(rewritten,"DROP INDEX CONCURRENTLY fi.") {
                t.Fatal("authoritative schema reference survived rewrite")
            }
            if strings.Contains(original,"REFERENCES fi.") &&
                !strings.Contains(rewritten,"REFERENCES fi_recovery_projection.") {
                t.Fatal("foreign-key relationships not redirected")
            }
            if name=="0004_security_field_name_index.sql" &&
                !strings.Contains(rewritten,
                    "DROP INDEX CONCURRENTLY fi_recovery_projection.windows_security_event_field_name_idx;") {
                t.Fatal("nontransactional index migration not preserved")
            }
            if name=="0001_relational.sql" {
                if !strings.Contains(rewritten,
                    "GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA fi_recovery_projection TO fi_ingest;") {
                    t.Fatal("private schema least-privilege grant absent")
                }
                if !strings.Contains(rewritten,
                    "GRANT CONNECT ON DATABASE fi TO fi_ingest;") {
                    t.Fatal("original database name unexpectedly changed")
                }
            }
        })
    }
}

func TestPrivateProjectionMigrationFailsClosed(t *testing.T) {
    valid:="-- Copyright (c) 2026 John Joseph Wood\nCREATE TABLE fi.source_record (id bigint);"
    if _,err:=RewritePrivateProjectionMigration("0006_unreviewed.sql",valid);err==nil {
        t.Fatal("unreviewed migration accepted")
    }
    if _,err:=RewritePrivateProjectionMigration("0002_source_families.sql","CREATE TABLE fi.x (id bigint);");err==nil {
        t.Fatal("missing canonical source provenance accepted")
    }
    if _,err:=RewritePrivateProjectionMigration("0002_source_families.sql",
        valid+"\n-- fi_recovery_projection must not already be present");err==nil {
        t.Fatal("already redirected migration accepted")
    }
}
