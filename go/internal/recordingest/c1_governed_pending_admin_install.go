//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// One-shot, explicitly operator-authorized SQL installation ON the existing
// PostgreSQL18 fi database inside fi-sor. No second database, old recovery
// schema, canonical row mutation, journal Accepted, or worker activation.
package recordingest

import (
    "context"
    "errors"
    "fmt"

    "github.com/jackc/pgx/v5"
)

// InstallC1GovernedPendingOnExistingSoR is a single SERIALIZABLE atomic
// transaction for ONLY C1 Pending DDL and the two least-privileged FI SQL
// service roles. Caller must separately authorize this OFFLINE action. It
// refuses remote/standby/non-superuser/unsupported cluster connections and
// never overwrites or alters any existing pending generation.
func InstallC1GovernedPendingOnExistingSoR(ctx context.Context,admin *pgx.Conn)error{
    if ctx==nil||admin==nil{
        return errors.New("C1 governed install: explicit PostgreSQL administrator and context required")
    }
    var database,user string
    var local,standby,superuser,canonical,alreadyPending,oldPrivate,oldLedger bool
    var version int
    err:=admin.QueryRow(ctx,`SELECT current_database(),current_user,
        inet_server_addr() IS NULL,pg_is_in_recovery(),
        (SELECT rolsuper FROM pg_roles WHERE rolname=current_user),
        to_regnamespace('fi') IS NOT NULL,
        to_regnamespace('fi_c1_pending') IS NOT NULL,
        to_regnamespace('fi_recovery_projection') IS NOT NULL,
        to_regnamespace('fi_recovery') IS NOT NULL,
        current_setting('server_version_num')::integer`).
        Scan(&database,&user,&local,&standby,&superuser,&canonical,
            &alreadyPending,&oldPrivate,&oldLedger,&version)
    if err!=nil{return err}
    if database!="fi"||user==""||!local||standby||!superuser||
        !canonical||alreadyPending||oldPrivate||oldLedger||
        version<180000||version>=190000{
        return errors.New("C1 governed install: requires existing canonical fi PostgreSQL18 on local Unix socket, pristine Pending and no private benchmark schemas")
    }
    tx,err:=admin.BeginTx(ctx,pgx.TxOptions{IsoLevel:pgx.Serializable})
    if err!=nil{return err}
    defer tx.Rollback(context.Background())
    if _,err=tx.Exec(ctx,"SELECT pg_advisory_xact_lock($1::bigint)",int64(0x46314331474f564e));err!=nil{
        return err
    }
    // Do not race an ingest acceptance or invent a second canonical SoR.
    if _,err=tx.Exec(ctx,"LOCK TABLE fi.recorded_generation,fi.ingest_journal IN SHARE MODE");err!=nil{
        return fmt.Errorf("C1 governed install: canonical acceptance lock: %w",err)
    }
    var pending,old,private,publisher bool
    err=tx.QueryRow(ctx,`SELECT
       to_regnamespace('fi_c1_pending') IS NOT NULL,
       to_regnamespace('fi_recovery') IS NOT NULL,
       to_regnamespace('fi_recovery_projection') IS NOT NULL,
       EXISTS(SELECT 1 FROM pg_roles WHERE rolname='fi_c1_publisher')`).
       Scan(&pending,&old,&private,&publisher)
    if err!=nil{return err}
    if pending||old||private||publisher{
        return errors.New("C1 governed install: stage or publisher role already exists; inspect read-only, never overwrite")
    }
    canonicalTables,err:=bootstrapListTables(ctx,tx,"fi")
    if err!=nil{return err}
    if len(canonicalTables)!=len(bootstrapSoRTables)||len(canonicalTables)!=49{
        return errors.New("C1 governed install: populated FI canonical 49-table contract changed")
    }
    if _,err=bootstrapSoRPromotionOrder(canonicalTables,nil);err!=nil{
        return fmt.Errorf("C1 governed install: canonical relational table graph mismatch: %w",err)
    }
    // A preexisting ordinary worker may be reused only if not privileged.
    // No PostgreSQL password/pg_hba change is made, and the fi-ingest
    // *jail* remains physically unable to open the fi-sor Unix socket.
    for _,item:=range []struct{name,create string}{
        {"fi_owner","CREATE ROLE fi_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION"},
        {"fi_ingest","CREATE ROLE fi_ingest LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION"},
    }{
        var exists,unsafe bool
        err=tx.QueryRow(ctx,`SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1),
          COALESCE((SELECT rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication
                    OR rolbypassrls FROM pg_roles WHERE rolname=$1),false)`,item.name).
            Scan(&exists,&unsafe)
        if err!=nil{return err}
        if unsafe{return fmt.Errorf("C1 governed install: preexisting %s role has unsafe cluster privileges",item.name)}
        if !exists{
            if _,err=tx.Exec(ctx,item.create);err!=nil{
                return fmt.Errorf("C1 governed install: create restricted SQL role %s: %w",item.name,err)
            }
        }
    }
    if _,err=tx.Exec(ctx,"GRANT CONNECT ON DATABASE fi TO fi_ingest");err!=nil{return err}
    if err=c1InstallGovernedPendingSchemaTx(ctx,tx);err!=nil{return err}
    for _,ddl:=range C1CanonicalPublisherRolePlan(){
        if _,err=tx.Exec(ctx,ddl);err!=nil{
            return fmt.Errorf("C1 governed install: publisher authority plan refused: %w",err)
        }
    }
    pendingTables,err:=bootstrapListTables(ctx,tx,c1GovernedPendingSchema)
    if err!=nil{return err}
    if len(pendingTables)!=len(canonicalTables)+1{
        return errors.New("C1 governed install: incomplete 49-table Pending mirror or governing control")
    }
    hasControl:=false
    for _,table:=range pendingTables{
        if table=="generation_control"{hasControl=true;break}
    }
    if !hasControl{return errors.New("C1 governed install: no governing control table")}
    if err=tx.Commit(ctx);err!=nil{
        return fmt.Errorf("C1 governed install: SQL commit uncertain; inspect Pending and roles read-only before any retry: %w",err)
    }
    fmt.Printf("FI C1 GOVERNED PENDING INSTALLED canonical_relations=%d pending_relations=%d publisher_role=%s canonical_data_unchanged=true c220_services_disabled=true\n",
        len(canonicalTables),len(pendingTables),c1PublisherRole)
    return nil
}
