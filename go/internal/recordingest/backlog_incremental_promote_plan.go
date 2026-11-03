// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
 "fmt"
 "strings"

 "github.com/jackc/pgx/v5"
)

// Canonical FK IDs are different from the private recovery sequence values.
// These are the ONLY identity-bearing columns in the governed 49-table model.
// Do not add a guessed mapping when the relational schema changes.
var sorPromotionFKMap = map[string]string{
 "recorded_generation_id":"recorded_generation",
 "source_batch_id":"source_batch",
 "source_record_id":"source_record",
 "ntfs_volume_id":"ntfs_volume",
 "ntfs_object_id":"ntfs_object",
 "parent_ntfs_object_id":"ntfs_object",
 "file_ntfs_object_id":"ntfs_object",
 "root_ntfs_object_id":"ntfs_object",
 "governed_root_id":"governed_root",
 "usn_read_boundary_source_record_id":"source_record",
}

var sorPromotionNaturalTables=map[string]bool{
 "ntfs_volume":true,"ntfs_object":true,"governed_root":true,
}

func sorPromotionMapName(table string) string {
 return "fi_promote_map_"+table
}
func sorPromotionMapSQL(table string) string {
 return pgx.Identifier{"pg_temp",sorPromotionMapName(table)}.Sanitize()
}

// compileSoRRemapSelect constructs a set-based INSERT SELECT for every family
// other than the three NTFS natural-identity tables. It preserves all original
// source values, replaces only database IDs, and gives canonical ingested_at
// one consistent acceptance timestamp. Quoted identifiers come from pg_catalog
// and are preflighted against the exact governed schema.
func compileSoRRemapSelect(table string,cols []bootstrapColumn)(string,error){
 if table=="ingest_journal" || sorPromotionNaturalTables[table]{
  return "",fmt.Errorf("FI SoR promotion: table %q needs dedicated handling",table)
 }
 known:=false
 for _,n:=range bootstrapSoRTables{if n==table{known=true;break}}
 if !known || len(cols)==0{return "",fmt.Errorf("FI SoR promotion: unapproved table %q",table)}
 names:=make([]string,0,len(cols))
 values:=make([]string,0,len(cols))
 joins:=make([]string,0,8)
 hasOwnID:=false
 for _,c:=range cols{
  col:=pgx.Identifier{c.name}.Sanitize()
  names=append(names,col)
  if c.name=="ingested_at"{
   values=append(values,"$1::timestamptz")
   continue
  }
  family,remap:=sorPromotionFKMap[c.name]
  if !remap {
   values=append(values,"src."+col)
   continue
  }
  if c.name==bootstrapIdentityColumns[table]{
   if family!=table{return "",fmt.Errorf("FI SoR promotion: invalid identity family %s.%s",table,c.name)}
   hasOwnID=true
  }
  alias:="m_"+c.name
  joinType:=" JOIN "
  if !c.notNull {joinType=" LEFT JOIN "}
  joins=append(joins,joinType+sorPromotionMapSQL(family)+" AS "+alias+
   " ON "+alias+".old_id = src."+col)
  // For nullable FKs with a non-null original value, a missing map is
  // explicitly detected by a separate fail-closed SQL check before insert.
  values=append(values,alias+".new_id")
 }
 if _,isIdentityTable:=bootstrapIdentityColumns[table];isIdentityTable&&!hasOwnID {
  return "",fmt.Errorf("FI SoR promotion: identity column absent in %q",table)
 }
 target:=pgx.Identifier{"fi",table}.Sanitize()
 private:=pgx.Identifier{privateProjectionSchema,table}.Sanitize()
 return "INSERT INTO "+target+" ("+strings.Join(names,",")+
  ") OVERRIDING SYSTEM VALUE SELECT "+strings.Join(values,",")+
  " FROM "+private+" AS src"+strings.Join(joins,""),nil
}
