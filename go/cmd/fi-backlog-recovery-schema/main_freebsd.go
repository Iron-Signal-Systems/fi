//go:build freebsd

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package main

import (
 "flag"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "strings"

 "github.com/Iron-Signal-Systems/fi/go/internal/recordingest"
)

func main(){
 if err:=run(os.Stdout);err!=nil{fmt.Fprintln(os.Stderr,"ERROR:",err);os.Exit(1)}
}

// Emits only the existing, PostgreSQL-tested private ledger schema and
// private rewrites of the FIVE approved canonical migrations.
// It NEVER connects to a database or applies its own SQL.
func run(w io.Writer)error{
 ledger:=flag.String("ledger-sql","","path to reviewed private recovery ledger SQL")
 migrations:=flag.String("migrations-dir","","path to canonical FI database/schema directory")
 flag.Parse()
 if flag.NArg()!=0||*ledger==""||*migrations==""||!filepath.IsAbs(*ledger)||!filepath.IsAbs(*migrations){
  return fmt.Errorf("absolute -ledger-sql and -migrations-dir required")
 }
 raw,err:=os.ReadFile(*ledger);if err!=nil{return err}
 if !strings.Contains(string(raw),"CREATE SCHEMA fi_recovery;")||
  !strings.Contains(string(raw),"CREATE TABLE fi_recovery.typed_window")||
  !strings.Contains(string(raw),"GRANT SELECT, INSERT ON fi_recovery.typed_window TO fi_ingest"){
  return fmt.Errorf("unrecognized private recovery ledger SQL")
 }
 if _,err:=fmt.Fprintln(w,"-- FI REAL BACKLOG PRIVATE RECOVERY SCHEMAS ONLY. NEVER DROP fi.*.");err!=nil{return err}
 if _,err:=w.Write(raw);err!=nil{return err}
 if _,err:=fmt.Fprintln(w,"");err!=nil{return err}
 for _,name:=range []string{"0001_relational.sql","0002_source_families.sql","0003_usn_relational_identity.sql","0004_security_field_name_index.sql","0005_usn_capture_binding.sql"}{
  src,err:=os.ReadFile(filepath.Join(*migrations,name));if err!=nil{return err}
  rewritten,err:=recordingest.RewritePrivateProjectionMigration(name,string(src));if err!=nil{return fmt.Errorf("%s: %w",name,err)}
  if _,err:=fmt.Fprintf(w,"\n-- FI private projection migration: %s\n",name);err!=nil{return err}
  if _,err:=io.WriteString(w,rewritten+"\n");err!=nil{return err}
 }
 return nil
}
