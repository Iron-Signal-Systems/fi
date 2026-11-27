//go:build freebsd && fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// One-shot SCHEMA ONLY installer into a physically isolated disposable PG18
// cluster inside fi-sor. It never connects to or copies live fi-sor PGDATA.
package main

import (
    "context"
    "errors"
    "flag"
    "fmt"
    "os"
    "path/filepath"
    "strings"
    "time"

    "github.com/Iron-Signal-Systems/fi/go/internal/freebsd/backendinstall"
    "github.com/Iron-Signal-Systems/fi/go/internal/recordingest"
    "github.com/jackc/pgx/v5"
)

func fail(err error){fmt.Fprintln(os.Stderr,"FI C1 DISPOSABLE CLONE BOOTSTRAP STOP:",err);os.Exit(1)}

func validateRoot(root string) error {
    clean:=filepath.Clean(root)
    if clean!=root||!filepath.IsAbs(root)||
        !strings.HasPrefix(root,"/var/tmp/fi-c1-sor-bench.")||
        strings.Contains(root,"..")||strings.Contains(root,"/var/db/fi/")||
        len(strings.TrimPrefix(root,"/var/tmp/fi-c1-sor-bench."))<8||
        strings.Contains(strings.TrimPrefix(root,"/var/tmp/fi-c1-sor-bench."),"/"){
        return errors.New("only a fresh /var/tmp/fi-c1-sor-bench.<unique> clone is eligible")
    }
    return nil
}

func run()error{
    f:=flag.NewFlagSet("fi-c1-sor-clone-bootstrap",flag.ContinueOnError)
    root:=f.String("clone-root","","isolated fi-sor scratch clone root")
    f.SetOutput(os.Stderr)
    if err:=f.Parse(os.Args[1:]);err!=nil{return err}
    if f.NArg()!=0{return errors.New("unexpected positional parameters")}
    if err:=validateRoot(*root);err!=nil{return err}
    if os.Geteuid()==0{return errors.New("refuse root: use unprivileged postgres OS account inside fi-sor")}
    data:=filepath.Join(*root,"pgdata")
    sock:=filepath.Join(*root,"socket")
    for _,dir:=range []string{*root,data,sock}{
        st,err:=os.Lstat(dir)
        if err!=nil||!st.IsDir()||st.Mode()&os.ModeSymlink!=0{
            return fmt.Errorf("clone root/data/socket is missing or symlinked: %s: %v",dir,err)
        }
        actual,err:=filepath.EvalSymlinks(dir)
        if err!=nil||actual!=dir{
            return fmt.Errorf("clone path resolution differs at %s: %v",dir,err)
        }
    }
    if _,err:=os.Stat(filepath.Join(data,"PG_VERSION"));err!=nil{
        return fmt.Errorf("missing initialized CLONE-ONLY PGDATA: %w",err)
    }
    ctx,cancel:=context.WithTimeout(context.Background(),20*time.Minute)
    defer cancel()
    dsn:=fmt.Sprintf("host=%s port=5432 dbname=fi user=postgres sslmode=disable",sock)
    config,err:=pgx.ParseConfig(dsn)
    if err!=nil{return err}
    if config.Host!=sock||config.Port!=5432||config.Database!="fi"||config.User!="postgres"{
        return errors.New("clone PostgreSQL DSN changed")
    }
    admin,err:=pgx.ConnectConfig(ctx,config)
    if err!=nil{return fmt.Errorf("isolated clone PostgreSQL admin connection: %w",err)}
    defer admin.Close(context.Background())
    var db,user,actualData,actualSock,listen,port string
    var version int
    var super,standby bool
    err=admin.QueryRow(ctx,`SELECT current_database(),current_user,
        current_setting('data_directory'),current_setting('unix_socket_directories'),
        current_setting('listen_addresses'),current_setting('port'),
        current_setting('server_version_num')::integer,
        (SELECT rolsuper FROM pg_roles WHERE rolname=current_user),
        pg_is_in_recovery()`).Scan(&db,&user,&actualData,&actualSock,&listen,&port,
        &version,&super,&standby)
    if err!=nil{return err}
    if db!="fi"||user!="postgres"||actualData!=data||actualSock!=sock||
        listen!=""||port!="5432"||version<180000||version>=190000||
        !super||standby||actualData=="/var/db/fi/sor/postgres"{
        return fmt.Errorf("REFUSE: physical PostgreSQL clone identity mismatch db=%s role=%s pgdata=%s socket=%s listen=%q port=%s version=%d",db,user,actualData,actualSock,listen,port,version)
    }
    var anySchema bool
    err=admin.QueryRow(ctx,`SELECT
        to_regnamespace('fi') IS NOT NULL OR
        to_regnamespace('fi_c1_pending') IS NOT NULL OR
        to_regnamespace('fi_recovery_projection') IS NOT NULL OR
        to_regnamespace('fi_recovery') IS NOT NULL OR
        EXISTS(SELECT 1 FROM pg_roles WHERE rolname IN
        ('fi_ingest','fi_owner','fi_c1_publisher'))`).Scan(&anySchema)
    if err!=nil{return err}
    if anySchema{return errors.New("clone not pristine; never reset or overwrite existing FI schema or roles")}
    // Exactly the same two restricted roles used by the real FI migrations.
    for _,sql:=range []string{
        "CREATE ROLE fi_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION",
        "CREATE ROLE fi_ingest LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION",
    }{
        if _,err=admin.Exec(ctx,sql);err!=nil{return fmt.Errorf("clone roles: %w",err)}
    }
    migrations,err:=backendinstall.C1CanonicalSchemaMigrations()
    if err!=nil{return err}
    if len(migrations)!=5{return errors.New("unexpected canonical migration count")}
    for _,m:=range migrations{
        if _,err=admin.Exec(ctx,m.SQL,pgx.QueryExecModeSimpleProtocol);err!=nil{
            return fmt.Errorf("clone-only canonical migration %s: %w",m.Name,err)
        }
    }
    if err=recordingest.InstallC1GovernedPendingOnExistingSoR(ctx,admin);err!=nil{
        return fmt.Errorf("clone-only governed Pending install: %w",err)
    }
    var canon,pending,accepted,fiTables,stageTables int64
    err=admin.QueryRow(ctx,`SELECT
        (SELECT count(*) FROM fi.recorded_generation),
        (SELECT count(*) FROM fi_c1_pending.generation_control),
        (SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted'),
        (SELECT count(*) FROM pg_tables WHERE schemaname='fi'),
        (SELECT count(*) FROM pg_tables WHERE schemaname='fi_c1_pending')`).
        Scan(&canon,&pending,&accepted,&fiTables,&stageTables)
    if err!=nil{return err}
    if canon!=0||pending!=0||accepted!=0||fiTables!=49||stageTables!=50{
        return fmt.Errorf("clone schema/row acceptance mismatch fi=%d pending=%d accepted=%d fiTables=%d pendingTables=%d",canon,pending,accepted,fiTables,stageTables)
    }
    // The normal worker may connect only over the newly constructed clone
    // socket. An attempt to connect to the real fi-sor service cannot pass
    // the clone PGDATA hard gate above.
    cfg:=recordingest.C1SoRLocalConfig{
        SourceID:"iss-fs-22a.iss.local",
        WorkerDSN:fmt.Sprintf("host=%s port=5432 dbname=fi user=fi_ingest sslmode=disable",sock),
        PublisherDSN:fmt.Sprintf("host=%s port=5432 dbname=fi user=fi_c1_publisher sslmode=disable",sock),
        SQLWorkersMax:32,
        Custody:recordingest.C1NativeBCustodyConfig{
            CustodyRoot:"/var/db/fi/custody/generation",
            RecordedRoot:"/var/db/fi/custody/recorded",
            MaxCanonicalBytes:75161927680,
            MaxEncodedBytes:68719476736,
            MaxManifestBytes:1048576,
        },
    }
    if err=recordingest.PreflightC1SoRLocal(ctx,cfg);err!=nil{
        return fmt.Errorf("clone worker governed Pending privilege/read-only preflight: %w",err)
    }
    fmt.Printf("FI C1 SOR DISPOSABLE CLONE SCHEMA PASS postgres18=true data_directory=%s unix_socket=%s tcp_listeners=none canonical_tables=49 pending_tables=50 canonical_generations=0 pending_generations=0 accepted=0 fi_ingest_worker_preflight=pass original_live_sor_untouched=true signed_custody_untouched=true\n",data,sock)
    return nil
}
func main(){if err:=run();err!=nil{fail(err)}}
