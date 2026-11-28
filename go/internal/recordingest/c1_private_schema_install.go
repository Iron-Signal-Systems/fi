//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// EXPLICIT OFFLINE C1 schema installer. Six checksum-validated canonical
// FI DDL files are rewritten to private fi_recovery_projection; the
// existing independently audited recovery ledger schema is unchanged.
// This does NOT modify existing populated canonical fi tables, accept a
// generation, install a service or grant fi-ingest any SQL access.
package recordingest

import (
    "context"
    "crypto/sha256"
    "encoding/hex"
    _ "embed"
    "errors"
    "fmt"
    "strings"

    "github.com/jackc/pgx/v5"
)

//go:embed backlog_artifact_ledger_schema.sql
var c1PrivateLedgerDDL string

type C1PrivateSchemaStatement struct {
    Name string
    SQL string
}

func c1MigrationWithoutTransactionEnvelope(source string)(string,error){
    const begin="\nBEGIN;\n"
    const end="\nCOMMIT;\n"
    beginCount:=strings.Count(source,begin)
    endCount:=strings.Count(source,end)
    if beginCount!=endCount||beginCount>1{
        return "",errors.New("C1 schema: unexpected canonical DDL transaction envelope")
    }
    if beginCount==1{
        source=strings.Replace(source,begin,"\n",1)
        source=strings.Replace(source,end,"\n",1)
    }
    if strings.Contains(source,"BEGIN;")||strings.Contains(source,"COMMIT;"){
        return "",errors.New("C1 schema: nested or noncanonical SQL transaction boundary")
    }
    return source,nil
}

// C1PrivateSchemaPlan is immutable, SHA-checked and has no SQL side
// effects. In a FRESH private schema only, remove the unused Security
// index with ordinary DROP INDEX: CONCURRENTLY is forbidden inside our
// ONE metadata transaction, and no C1 SQL workers have yet started.
func C1PrivateSchemaPlan()([]C1PrivateSchemaStatement,error){
    originals,err:=c1CanonicalSchemaMigrations()
    if err!=nil{return nil,err}
    plan:=make([]C1PrivateSchemaStatement,0,len(originals)+1)
    for _,src:=range originals{
        ddl,err:=RewritePrivateProjectionMigration(src.Name,src.SQL)
        if err!=nil{return nil,err}
        if src.Name=="0004_security_field_name_index.sql"{
            const old="DROP INDEX CONCURRENTLY fi_recovery_projection.windows_security_event_field_name_idx;"
            if strings.Count(ddl,old)!=1{
                return nil,errors.New("C1 schema: Security index migration is not the audited private-only DROP")
            }
            ddl=strings.Replace(ddl,old,
                "DROP INDEX fi_recovery_projection.windows_security_event_field_name_idx;",1)
        }
        ddl,err=c1MigrationWithoutTransactionEnvelope(ddl)
        if err!=nil{return nil,fmt.Errorf("C1 schema: migration %s transaction: %w",src.Name,err)}
        if strings.Contains(ddl,"fi.")||strings.Contains(ddl,"DROP TABLE")||
            strings.Contains(ddl,"DROP SCHEMA"){
            return nil,fmt.Errorf("C1 schema: unapproved authoritative/unsafe DDL in %s",src.Name)
        }
        plan=append(plan,C1PrivateSchemaStatement{Name:src.Name,SQL:ddl})
    }
    ledger,err:=c1MigrationWithoutTransactionEnvelope(c1PrivateLedgerDDL)
    if err!=nil{return nil,err}
    if !strings.Contains(ledger,"CREATE SCHEMA fi_recovery;")||
        !strings.Contains(ledger,"CREATE TABLE fi_recovery.typed_window")||
        strings.Contains(ledger,"CREATE TABLE fi.")||
        strings.Contains(ledger,"INSERT INTO fi.")||
        strings.Contains(ledger,"DROP TABLE")||
        strings.Contains(ledger,"DROP SCHEMA"){
        return nil,errors.New("C1 schema: unapproved private recovery ledger")
    }
    plan=append(plan,C1PrivateSchemaStatement{Name:"fi_recovery_private_ledger",SQL:ledger})
    if len(plan)!=7{return nil,errors.New("C1 schema: missing full private staging DDL")}
    return plan,nil
}

// c1InstallPrivateSchemaTx is called only after the separate ADMIN local
// socket and empty schema preflight. The entire private schema creation is
// rolled back on any error; unlike the original migration scripts, no DDL
// transaction is committed before other private schemas are complete.
func c1InstallPrivateSchemaTx(ctx context.Context,tx pgx.Tx)error{
    if ctx==nil||tx==nil{return errors.New("C1 schema: owning SQL transaction required")}
    plan,err:=C1PrivateSchemaPlan()
    if err!=nil{return err}
    for _,script:=range plan{
        if _,err=tx.Exec(ctx,script.SQL,pgx.QueryExecModeSimpleProtocol);err!=nil{
            return fmt.Errorf("C1 schema: private DDL %s: %w",script.Name,err)
        }
    }
    // PostgreSQL's default new-schema/table privileges exclude fi_ingest.
    // The *fi-sor jail* C1 writer uses the fi_ingest DATABASE role on its
    // local Unix socket. Without explicit private-only grants the very
    // first SourceParent COPY fails despite successful DDL/CI compilation.
    // These grants are part of this SAME atomic offline transaction; no
    // GRANT touches canonical fi, and no schema CREATE/TRUNCATE privilege is
    // delegated. fi-ingest jail itself never gets any PostgreSQL socket.
    for _,statement:=range []string{
        "GRANT USAGE ON SCHEMA fi_recovery_projection, fi_recovery TO fi_ingest",
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA fi_recovery_projection, fi_recovery TO fi_ingest",
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA fi_recovery_projection, fi_recovery TO fi_ingest",
    }{
        if _,err=tx.Exec(ctx,statement);err!=nil{
            return fmt.Errorf("C1 schema: atomic private SoR writer role privileges: %w",err)
        }
    }
    return nil
}

// InstallC1PrivateSchemas is for an explicit one-time OFFLINE PostgreSQL
// administrator session inside fi-sor on a LOCAL UNIX SOCKET only. It
// refuses an existing private stage, an uninitialized canonical fi schema,
// standby databases, remote SQL and non-superuser connections. It creates
// ONLY two new private schemas in ONE transaction.
func InstallC1PrivateSchemas(ctx context.Context,admin *pgx.Conn)error{
    if ctx==nil||admin==nil{return errors.New("C1 schema: local administrator session required")}
    var database,role string
    var local,recovery,superuser,canonical,privateProjection,ledger bool
    var version int
    err:=admin.QueryRow(ctx,`SELECT current_database(),current_user,
        inet_server_addr() IS NULL,pg_is_in_recovery(),
        (SELECT rolsuper FROM pg_roles WHERE rolname=current_user),
        to_regnamespace('fi') IS NOT NULL,
        to_regnamespace('fi_recovery_projection') IS NOT NULL,
        to_regnamespace('fi_recovery') IS NOT NULL,
        current_setting('server_version_num')::integer`).
        Scan(&database,&role,&local,&recovery,&superuser,&canonical,
            &privateProjection,&ledger,&version)
    if err!=nil{return err}
    if database!="fi"||role==""||!local||recovery||!superuser||
        !canonical||privateProjection||ledger||version<180000{
        return errors.New("C1 schema: requires clean private namespaces on a local PostgreSQL18 fi administrative session")
    }
    var ingestRolePresent bool
    if err=admin.QueryRow(ctx,`SELECT EXISTS(
        SELECT 1 FROM pg_roles WHERE rolname='fi_ingest')`).
        Scan(&ingestRolePresent);err!=nil{return err}
    if !ingestRolePresent{
        return errors.New("C1 schema: local fi_ingest SQL writer role must exist before private DDL")
    }
    tx,err:=admin.Begin(ctx)
    if err!=nil{return err}
    defer tx.Rollback(context.Background())
    // Protect any concurrent offline installer from racing the private
    // schema preflight; conditional CREATE grants no replay authority.
    if _,err=tx.Exec(ctx,"SELECT pg_advisory_xact_lock($1::bigint)",int64(0x4631433150524956));err!=nil{
        return err
    }
    var existing bool
    if err=tx.QueryRow(ctx,`SELECT to_regnamespace('fi_recovery_projection') IS NOT NULL
        OR to_regnamespace('fi_recovery') IS NOT NULL`).Scan(&existing);err!=nil{return err}
    if existing{return errors.New("C1 schema: private namespace appeared during creation")}
    if err=c1InstallPrivateSchemaTx(ctx,tx);err!=nil{return err}
    if err=tx.Commit(ctx);err!=nil{
        return fmt.Errorf("C1 schema: private DDL commit outcome uncertain; inspect both namespaces before retry: %w",err)
    }
    plan,_:=C1PrivateSchemaPlan()
    h:=sha256.New()
    for _,script:=range plan{h.Write([]byte(script.Name));h.Write([]byte(script.SQL))}
    fmt.Printf("FI C1 PRIVATE SCHEMAS INSTALLED count=2 migration_plan_sha256=%s canonical_mutation=false services_started=false\n",
        hex.EncodeToString(h.Sum(nil)))
    return nil
}
