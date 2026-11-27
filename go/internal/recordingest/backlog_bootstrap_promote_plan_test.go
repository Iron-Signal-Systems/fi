package recordingest

import (
 "os"
 "path/filepath"
 "regexp"
 "strings"
 "testing"
)

func TestBootstrapSoRPlanCoversExactly49MigrationTables(t *testing.T) {
 ddl:=strings.Builder{}
 for _,file:=range []string{"0001_relational.sql","0002_source_families.sql"}{
  b,err:=os.ReadFile(filepath.Join("..","..","..","database","schema",file))
  if err!=nil{t.Fatal(err)}
  ddl.Write(b)
 }
 re:=regexp.MustCompile(`(?m)^CREATE TABLE fi\.([a-z0-9_]+) \(`)
 matches:=re.FindAllStringSubmatch(ddl.String(),-1)
 var tables []string
 for _,match:=range matches {tables=append(tables,match[1])}
 if len(tables)!=49 {t.Fatalf("relational DDL changed: found %d table names",len(tables))}
 order,err:=bootstrapSoRPromotionOrder(tables,nil)
 if err!=nil {t.Fatal(err)}
 if len(order)!=48 {t.Fatal("promotion lost or duplicated one table")}
 if _,ok:=bootstrapIdentityColumns["source_record"];!ok {t.Fatal("source record identity omitted")}
}

func TestBootstrapSoRPlanPreservesFKOrderAndFailsClosed(t *testing.T) {
 tables:=append([]string(nil),bootstrapSoRTables...)
 edges:=[][2]string{
  {"source_batch","recorded_generation"},
  {"source_record","source_batch"},
  {"windows_security_event","source_record"},
  {"windows_security_event_field","windows_security_event"},
  {"usn_object_change_reason","usn_object_change"},
  {"usn_object_change","usn_object_observation"},
 }
 order,err:=bootstrapSoRPromotionOrder(tables,edges)
 if err!=nil {t.Fatal(err)}
 pos:=make(map[string]int)
 for i,n:=range order{pos[n]=i}
 for _,pair:=range edges {
  if pos[pair[1]]>=pos[pair[0]]{t.Fatalf("child %s preceded parent %s",pair[0],pair[1])}
 }
 if _,err:=bootstrapSoRPromotionOrder(tables,append(edges,[2]string{"source_batch","source_record"}));err==nil{
  t.Fatal("cyclic FK plan accepted")
 }
 if _,err:=bootstrapSoRPromotionOrder(append(tables,"unapproved_table"),nil);err==nil{
  t.Fatal("new table silently excluded from publication")
 }
 if _,err:=bootstrapSoRPromotionOrder(tables[:48],nil);err==nil{
  t.Fatal("missing table silently accepted")
 }
}
