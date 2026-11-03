// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
 "context"
 "fmt"

 "github.com/jackc/pgx/v5"
)

type sorPromotionFKColumn struct{
 child,childColumn,parent,parentColumn string
}

// PostgreSQL is the authority for multi-column FKs: checking only table-level
// dependency order is insufficient when source_record_id/NTFS identity columns
// are remapped across canonical generations.
func readSoRPromotionFKColumns(ctx context.Context,tx pgx.Tx,schema string)([]sorPromotionFKColumn,error){
 rows,err:=tx.Query(ctx,`SELECT child.relname, child_att.attname,
 parent.relname, parent_att.attname
 FROM pg_constraint fk
 JOIN pg_class child ON child.oid=fk.conrelid
 JOIN pg_namespace child_ns ON child_ns.oid=child.relnamespace
 JOIN pg_class parent ON parent.oid=fk.confrelid
 JOIN pg_namespace parent_ns ON parent_ns.oid=parent.relnamespace
 CROSS JOIN LATERAL generate_subscripts(fk.conkey,1) AS pos
 JOIN pg_attribute child_att ON child_att.attrelid=fk.conrelid
  AND child_att.attnum=fk.conkey[pos]
 JOIN pg_attribute parent_att ON parent_att.attrelid=fk.confrelid
  AND parent_att.attnum=fk.confkey[pos]
 WHERE fk.contype='f' AND child_ns.nspname=$1
  AND parent_ns.nspname=$1
 ORDER BY child.relname,child_att.attname,parent.relname,parent_att.attname`,schema)
 if err!=nil{return nil,err}
 defer rows.Close()
 var out []sorPromotionFKColumn
 for rows.Next(){
  var item sorPromotionFKColumn
  if err=rows.Scan(&item.child,&item.childColumn,&item.parent,&item.parentColumn);err!=nil{return nil,err}
  out=append(out,item)
 }
 return out,rows.Err()
}
func checkSoRPromotionFKColumns(canonical,private []sorPromotionFKColumn)error{
 if len(canonical)==0||len(canonical)!=len(private){
  return fmt.Errorf("FI SoR promotion: incomplete FK graph canonical=%d private=%d",len(canonical),len(private))
 }
 for i,k:=range canonical{
  if k!=private[i]{return fmt.Errorf("FI SoR promotion: private FK graph differs at %d: %+v != %+v",i,k,private[i])}
  // If the referenced PK/UK column is a generated ID family, the
  // referencing column must resolve through EXACTLY the same map.
  parentMap,required:=sorPromotionFKMap[k.parentColumn]
  childMap,childMapped:=sorPromotionFKMap[k.childColumn]
  if required && (!childMapped || childMap!=parentMap){
   return fmt.Errorf("FI SoR promotion: missing/mismatched map for %s.%s -> %s.%s",
    k.child,k.childColumn,k.parent,k.parentColumn)
  }
  if childMapped && !required{
   return fmt.Errorf("FI SoR promotion: mapped FK column %s.%s references unmapped %s.%s",
    k.child,k.childColumn,k.parent,k.parentColumn)
  }
 }
 return nil
}
func verifySoRPromotionForeignKeys(ctx context.Context,tx pgx.Tx)error{
 canonical,err:=readSoRPromotionFKColumns(ctx,tx,"fi")
 if err!=nil{return err}
 private,err:=readSoRPromotionFKColumns(ctx,tx,privateProjectionSchema)
 if err!=nil{return err}
 return checkSoRPromotionFKColumns(canonical,private)
}
