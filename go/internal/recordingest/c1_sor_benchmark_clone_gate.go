//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// The benchmark gate binds BOTH worker and publisher connections to the
// physically distinct disposable PG18 instance. Unlike a DSN hostname
// comparison, PostgreSQL reports its actual PGDATA after connecting.
// This gate is read-only and must pass before any signed generation loads.
package recordingest

import (
    "context"
    "errors"
    "fmt"
    "os"
    "path/filepath"
    "strings"

    "github.com/jackc/pgx/v5"
)

func c1ValidateIsolatedBenchmarkRoot(root string)error{
    if !filepath.IsAbs(root)||filepath.Clean(root)!=root||
        !strings.HasPrefix(root,"/var/tmp/fi-c1-sor-bench.")||
        len(strings.TrimPrefix(root,"/var/tmp/fi-c1-sor-bench."))<8||
        strings.Contains(strings.TrimPrefix(root,"/var/tmp/fi-c1-sor-bench."),"/")||
        strings.Contains(root,"..")||
        root=="/var/db/fi/sor/postgres"{
        return errors.New("C1 benchmark: refusing unknown or live PostgreSQL clone root")
    }
    for _,path:=range []string{root,filepath.Join(root,"pgdata"),filepath.Join(root,"socket")}{
        st,err:=os.Lstat(path)
        if err!=nil||!st.IsDir()||st.Mode()&os.ModeSymlink!=0{
            return fmt.Errorf("C1 benchmark: clone path missing or symlinked %s: %v",path,err)
        }
        real,err:=filepath.EvalSymlinks(path)
        if err!=nil||real!=path{
            return fmt.Errorf("C1 benchmark: clone path resolves unexpectedly %s: %v",path,err)
        }
    }
    return nil
}

// PreflightC1SoRBenchmarkClone verifies the exact isolated cluster; neither
// the live SQL socket nor a different PostgreSQL instance can satisfy it.
func PreflightC1SoRBenchmarkClone(ctx context.Context,c C1SoRLocalConfig,root,expectedSystemID string)error{
    if ctx==nil{return errors.New("C1 benchmark: missing context")}
    if err:=validateC1SoRLocalConfig(c);err!=nil{return err}
    if err:=c1ValidateIsolatedBenchmarkRoot(root);err!=nil{return err}
    if len(expectedSystemID)<12||len(expectedSystemID)>22{
        return errors.New("C1 benchmark: required exact PostgreSQL system identifier missing")
    }
    for _,digit:=range expectedSystemID{
        if digit<'0'||digit>'9'{return errors.New("C1 benchmark: malformed PostgreSQL system identifier")}
    }
    data,sock:=filepath.Join(root,"pgdata"),filepath.Join(root,"socket")
    worker,err:=pgx.ParseConfig(c.WorkerDSN)
    if err!=nil{return err}
    publisher,err:=pgx.ParseConfig(c.PublisherDSN)
    if err!=nil{return err}
    for i,role:=range []struct{config *pgx.ConnConfig;name string}{
        {worker,"fi_ingest"},{publisher,"fi_c1_publisher"},
    }{
        if role.config.Host!=sock||role.config.Port!=5432||
            role.config.Database!="fi"||role.config.User!=role.name{
            return fmt.Errorf("C1 benchmark: SQL connection %d not pinned to isolated clone Unix socket",i)
        }
    }
    for _,dsn:=range []struct{config *pgx.ConnConfig; role string}{
        {worker,"fi_ingest"},{publisher,"fi_c1_publisher"},
    }{
        conn,err:=pgx.ConnectConfig(ctx,dsn.config)
        if err!=nil{return fmt.Errorf("C1 benchmark: local %s connection: %w",dsn.role,err)}
        var db,user,port,actualSystemID string
        var serverIP,clientIP *string
        var standby bool
        var version int
        // The normal SQL worker has no pg_read_all_settings privilege.
        // Its socket DSN plus this PostgreSQL-control-file identifier
        // binds it to the SAME exact cluster that the host postgres
        // administrator identified by the physical PGDATA path.
        err=conn.QueryRow(ctx,`SELECT current_database(),current_user,
            current_setting('port'),current_setting('server_version_num')::integer,
            pg_is_in_recovery(),inet_server_addr()::text,inet_client_addr()::text,
            (SELECT system_identifier::text FROM pg_control_system())`).
            Scan(&db,&user,&port,&version,&standby,&serverIP,&clientIP,&actualSystemID)
        _=conn.Close(context.Background())
        if err!=nil{return fmt.Errorf("C1 benchmark: SQL system identity query for role %s: %w",dsn.role,err)}
        if actualSystemID!=expectedSystemID||db!="fi"||user!=dsn.role||
            port!="5432"||version<180000||version>=190000||standby||
            serverIP!=nil||clientIP!=nil {
            return fmt.Errorf("C1 benchmark: rejecting foreign cluster identity role=%s system_identifier=%s db=%s",user,actualSystemID,db)
        }
    }
    conn,_,err:=openC1SoRLocalSQL(ctx,c.WorkerDSN,"")
    if err!=nil{return err}
    defer conn.Close(context.Background())
    var canonical,pending,accepted,fiTables,pendingTables int64
    err=conn.QueryRow(ctx,`SELECT
        (SELECT count(*) FROM fi.recorded_generation),
        (SELECT count(*) FROM fi_c1_pending.generation_control),
        (SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted'),
        (SELECT count(*) FROM pg_tables WHERE schemaname='fi'),
        (SELECT count(*) FROM pg_tables WHERE schemaname='fi_c1_pending')`).
        Scan(&canonical,&pending,&accepted,&fiTables,&pendingTables)
    if err!=nil{return err}
    if canonical!=0||pending!=0||accepted!=0||fiTables!=49||pendingTables!=50{
        return fmt.Errorf("C1 benchmark: clone is not fresh 49+50 schema: canonical=%d pending=%d accepted=%d tables=%d+%d",canonical,pending,accepted,fiTables,pendingTables)
    }
    if c.DirectCanonicalClone{
        // This is a physically isolated, EMPTY PostgreSQL clone. Canonical
        // INSERT privileges are mandatory in this test ONLY; the normal
        // pending-mode runtime must not accept these broader grants.
        var missingTable,mutableTable,missingSeq int64
        err=conn.QueryRow(ctx,`SELECT
          count(*) FILTER (WHERE c.relkind IN ('r','p') AND
             NOT (has_table_privilege(current_user,c.oid,'SELECT') AND
                  has_table_privilege(current_user,c.oid,'INSERT')))::bigint,
          count(*) FILTER (WHERE c.relkind IN ('r','p') AND
             (has_table_privilege(current_user,c.oid,'UPDATE') OR
              has_table_privilege(current_user,c.oid,'DELETE') OR
              has_table_privilege(current_user,c.oid,'TRUNCATE')))::bigint,
          count(*) FILTER (WHERE c.relkind='S' AND
             NOT (has_sequence_privilege(current_user,c.oid,'USAGE') AND
                  has_sequence_privilege(current_user,c.oid,'SELECT')))::bigint
          FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
          WHERE n.nspname='fi'`).Scan(&missingTable,&mutableTable,&missingSeq)
        if err!=nil{return err}
        if missingTable!=0||mutableTable!=0||missingSeq!=0{
            return fmt.Errorf("C1 direct clone: canonical worker ACL missing tables=%d mutable=%d sequences=%d",
                missingTable,mutableTable,missingSeq)
        }
    }else{
        if err:=c1PreflightLocalGovernedPendingSQL(ctx,c.WorkerDSN);err!=nil{return err}
    }
    fmt.Printf("FI C1 SOR CLONE WORKER/PUBLISHER PIN PASS pgdata=%s socket=%s postgres_system_identifier=%s canonical=0 pending=0 accepted=0 direct_canonical_clone=%t readonly_gate=true\n",
        data,sock,expectedSystemID,c.DirectCanonicalClone)
    return nil
}
