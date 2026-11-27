package recordingest

import (
 "strings"
 "testing"
)

func TestSoRRemapSQLPreservesSignedFieldsAndChangesDatabaseIDs(t *testing.T){
 cols:=[]bootstrapColumn{
  {name:"source_record_id",typeName:"bigint",notNull:true},
  {name:"field_ordinal",typeName:"integer",notNull:true},
  {name:"name",typeName:"text",notNull:true},
  {name:"value",typeName:"text",notNull:true},
 }
 query,err:=compileSoRRemapSelect("windows_security_event_field",cols)
 if err!=nil{t.Fatal(err)}
 if !strings.Contains(query,`JOIN "pg_temp"."fi_promote_map_source_record" AS m_source_record_id`) ||
  !strings.Contains(query,`m_source_record_id.new_id`) ||
  !strings.Contains(query,`src."field_ordinal"`) ||
  !strings.Contains(query,`src."value"`){
  t.Fatal("Security field mapping changed original child ordinal or value: "+query)
 }
}
func TestSoRRemapSQLIncludesOptionalAndCrossFamilyFKs(t *testing.T){
 cols:=[]bootstrapColumn{
  {name:"source_record_id",notNull:true},
  {name:"governed_root_id",notNull:true},
  {name:"ntfs_object_id",notNull:true},
  {name:"parent_ntfs_object_id",notNull:false},
  {name:"observed_at",notNull:true},
 }
 q,err:=compileSoRRemapSelect("file_observation",cols)
 if err!=nil{t.Fatal(err)}
 for _,term:=range []string{
  `JOIN "pg_temp"."fi_promote_map_source_record"`,
  `JOIN "pg_temp"."fi_promote_map_governed_root"`,
  `JOIN "pg_temp"."fi_promote_map_ntfs_object"`,
  `LEFT JOIN "pg_temp"."fi_promote_map_ntfs_object" AS m_parent_ntfs_object_id`,
  `src."observed_at"`,
 }{
  if !strings.Contains(q,term){t.Fatalf("missing %s from %s",term,q)}
 }
}
func TestSoRRemapSQLRejectsUnknownAndNaturalTables(t *testing.T){
 for _,table:=range []string{"ingest_journal","governed_root","ntfs_object","ntfs_volume","unapproved"}{
  if _,err:=compileSoRRemapSelect(table,[]bootstrapColumn{{name:"source_record_id"}});err==nil{
   t.Fatalf("unapproved %s accepted",table)
  }
 }
 if _,err:=compileSoRRemapSelect("source_record",[]bootstrapColumn{{name:"record_kind"}});err==nil{
  t.Fatal("source_record identity could be omitted")
 }
}
