package recordingest

import (
    "strings"
    "testing"
)

func TestBacklogWindowCoverageDoesNotReadCanonicalWhenAuditingC1Pending(t *testing.T) {
    for _,tc:=range []struct{
        schema string
        want string
    }{
        {"fi","\"fi\".source_record"},
        {"fi_c1_pending","\"fi_c1_pending\".source_record"},
        {"fi_recovery_projection","\"fi_recovery_projection\".source_record"},
    }{
        sql,err:=backlogWindowCoverageSQL(tc.schema)
        if err!=nil{t.Fatalf("approved schema %s: %v",tc.schema,err)}
        if !strings.Contains(sql,tc.want) ||
            strings.Count(sql,"\""+tc.schema+"\".")<13{
            t.Fatalf("typed-root coverage not fully bound to %s",tc.schema)
        }
        if tc.schema!="fi" && strings.Contains(sql,"FROM fi.") {
            t.Fatalf("C1 typed-root read silently fell through to canonical fi for %s",tc.schema)
        }
    }
    for _,selected:=range [][]string{
        {""},{"pg_catalog"},{"fi; DROP SCHEMA fi CASCADE"},{"fi_c1_pending","fi"},
    }{
        if _,err:=backlogWindowCoverageSQL(selected...);err==nil{
            t.Fatalf("unapproved SQL schema selection accepted: %v",selected)
        }
    }
    sql,err:=backlogWindowCoverageSQL()
    if err!=nil||!strings.Contains(sql,"\"fi\".source_record"){
        t.Fatalf("previous canonical window coverage changed: %v",err)
    }
}
