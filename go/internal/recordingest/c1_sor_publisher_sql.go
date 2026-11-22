//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// C1 publication is a separate fi-sor-local PostgreSQL authority, NOT the
// fi_ingest SQL worker. It holds the strong canonical locks needed to make
// one accepted generation atomically visible; ingest workers never obtain
// the publisher DSN, privileges, passfile, or network database access.
package recordingest

import (
    "context"
    "errors"
    "fmt"
    "path/filepath"
    "strings"

    "github.com/jackc/pgx/v5"
)

// Dedicated local role; its credential is a fi-sor-only secret and is never
// passed to fi-ingest, C1 frames, RAM objects or the independent B child.
const c1PublisherRole="fi_c1_publisher"

func c1SoRLocalPublisherConfig(dsn string)(*pgx.ConnConfig,error){
    if dsn==""{return nil,errors.New("C1 canonical: separate local publisher DSN required")}
    config,err:=pgx.ParseConfig(dsn)
    if err!=nil{return nil,err}
    if config.Database!="fi"||config.User!=c1PublisherRole||config.Port!=5432||
        !filepath.IsAbs(config.Host)||filepath.Clean(config.Host)!=config.Host||
        strings.Contains(config.Host,".."){
        return nil,errors.New("C1 canonical: publisher must use dedicated fi_c1_publisher role on fi-sor Unix-domain PostgreSQL")
    }
    return config,nil
}

func openC1SoRLocalPublisherSQL(ctx context.Context,dsn string)(*pgx.Conn,error){
    if ctx==nil{return nil,errors.New("C1 canonical: publisher context required")}
    config,err:=c1SoRLocalPublisherConfig(dsn)
    if err!=nil{return nil,err}
    conn,err:=pgx.ConnectConfig(ctx,config)
    if err!=nil{return nil,err}
    var db,user string
    var recovery,superuser bool
    var serverIP,clientIP *string
    err=conn.QueryRow(ctx,`SELECT current_database(),current_user,
        pg_is_in_recovery(),(SELECT rolsuper FROM pg_roles WHERE rolname=current_user),
        inet_server_addr()::text,inet_client_addr()::text`).
        Scan(&db,&user,&recovery,&superuser,&serverIP,&clientIP)
    if err!=nil||db!="fi"||user!=c1PublisherRole||recovery||superuser||
        serverIP!=nil||clientIP!=nil{
        _=conn.Close(context.Background())
        return nil,fmt.Errorf("C1 canonical: rejected remote, superuser, standby or wrong-role publisher: %v",err)
    }
    return conn,nil
}

// Read-only SQL authorization survey for a separate least-privileged SoR
// publisher. The normal fi_ingest worker must NOT gain canonical MAINTAIN/UPDATE,
// DELETE or TRUNCATE just to satisfy PostgreSQL strong table locks.
func c1ReadOnlyPublisherPrivileges(ctx context.Context,tx pgx.Tx)error{
    if ctx==nil||tx==nil{return errors.New("C1 canonical: read-only publisher privilege preflight required")}
    var role string
    var lock,insertJournal,pendingRead,pendingLock,pendingTruncate,pendingWrite,canonicalUpdate,canonicalTruncate,seqUsage bool
    err:=tx.QueryRow(ctx,`SELECT current_user,
       has_table_privilege(current_user,'fi.source_record','MAINTAIN'),
       has_table_privilege(current_user,'fi.ingest_journal','INSERT'),
       has_table_privilege(current_user,'fi_c1_pending.generation_control','SELECT'),
       has_table_privilege(current_user,'fi_c1_pending.generation_control','MAINTAIN'),
       has_table_privilege(current_user,'fi_c1_pending.generation_control','TRUNCATE'),
       has_table_privilege(current_user,'fi_c1_pending.generation_control','UPDATE'),
       has_table_privilege(current_user,'fi.source_record','UPDATE'),
       has_table_privilege(current_user,'fi.source_record','TRUNCATE'),
       has_sequence_privilege(current_user,
         pg_get_serial_sequence('fi.recorded_generation','recorded_generation_id')::regclass,'USAGE')`).
       Scan(&role,&lock,&insertJournal,&pendingRead,&pendingLock,&pendingTruncate,&pendingWrite,
           &canonicalUpdate,&canonicalTruncate,&seqUsage)
    if err!=nil{return err}
    if role!=c1PublisherRole||!lock||!insertJournal||!pendingRead||
        !pendingLock||!pendingTruncate||pendingWrite||canonicalUpdate||canonicalTruncate||!seqUsage{
        return errors.New("C1 canonical: absent/wrong privilege for dedicated locking publisher")
    }
    return nil
}

func c1PreflightLocalPublisher(ctx context.Context,dsn string)error{
    conn,err:=openC1SoRLocalPublisherSQL(ctx,dsn)
    if err!=nil{return err}
    defer conn.Close(context.Background())
    tx,err:=conn.BeginTx(ctx,pgx.TxOptions{IsoLevel:pgx.RepeatableRead,AccessMode:pgx.ReadOnly})
    if err!=nil{return err}
    defer tx.Rollback(context.Background())
    if err=c1ReadOnlyPublisherPrivileges(ctx,tx);err!=nil{return err}
    return tx.Commit(ctx)
}
