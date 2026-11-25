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
func PreflightC1SoRBenchmarkClone(ctx context.Context,c C1SoRLocalConfig,root string)error{
    if ctx==nil{return errors.New("C1 benchmark: missing context")}
    if err:=validateC1SoRLocalConfig(c);err!=nil{return err}
    if err:=c1ValidateIsolatedBenchmarkRoot(root);err!=nil{return err}
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
        var actualData,actualSocket,listen,db,user,port string
        var standby bool
        var version int
        err=conn.QueryRow(ctx,`SELECT current_setting('data_directory'),
            current_setting('unix_socket_directories'),current_setting('listen_addresses'),
            current_database(),current_user,current_setting('port'),
            current_setting('server_version_num')::integer,pg_is_in_recovery()`).
            Scan(&actualData,&actualSocket,&listen,&db,&user,&port,&version,&standby)
        _=conn.Close(context.Background())
        if err!=nil{return fmt.Errorf("C1 benchmark: SQL identity query: %w",err)}
        if actualData!=data||actualSocket!=sock||listen!=""||db!="fi"||
            user!=dsn.role||port!="5432"||version<180000||version>=190000||standby {
            return fmt.Errorf("C1 benchmark: refusing physical SQL identity mismatch role=%s pgdata=%s socket=%s tcp=%q",user,actualData,actualSocket,listen)
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
    if err:=c1PreflightLocalGovernedPendingSQL(ctx,c.WorkerDSN);err!=nil{return err}
    fmt.Printf("FI C1 SOR CLONE WORKER/PUBLISHER PIN PASS pgdata=%s socket=%s canonical=0 pending=0 accepted=0 readonly_gate=true\n",data,sock)
    return nil
}
