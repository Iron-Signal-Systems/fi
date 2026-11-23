//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// The C1 native shared SQL pool executes ONLY within the fi-sor jail.
// A local Unix-domain PostgreSQL socket is required. The ingest jail never
// opens these connections and never receives the PostgreSQL passfile.
package recordingest

import (
    "context"
    "errors"
    "fmt"
    "path/filepath"
    "strings"

    "github.com/jackc/pgx/v5"
)

func c1SoRLocalConnectionConfig(dsn string)(*pgx.ConnConfig,error){
    if dsn==""{return nil,errors.New("C1 fi-sor: PostgreSQL DSN required")}
    config,err:=pgx.ParseConfig(dsn)
    if err!=nil{return nil,err}
    if config.Database!="fi"||config.User!="fi_ingest"||config.Port!=5432||
        !filepath.IsAbs(config.Host)||filepath.Clean(config.Host)!=config.Host||
        strings.Contains(config.Host,"..") {
        return nil,errors.New("C1 fi-sor: SQL pool must use fi_ingest/fi on a local Unix-domain PostgreSQL socket")
    }
    return config,nil
}
func openC1SoRLocalSQL(ctx context.Context,dsn,_ string)(*pgx.Conn,int64,error){
    if ctx==nil{return nil,0,errors.New("C1 fi-sor: missing connection context")}
    config,err:=c1SoRLocalConnectionConfig(dsn)
    if err!=nil{return nil,0,err}
    conn,err:=pgx.ConnectConfig(ctx,config)
    if err!=nil{return nil,0,err}
    var database,user string
    var inRecovery bool
    var pid int64
    var serverIP,clientIP *string
    err=conn.QueryRow(ctx,`SELECT current_database(),current_user,pg_is_in_recovery(),
        pg_backend_pid()::bigint,inet_server_addr()::text,inet_client_addr()::text`).
        Scan(&database,&user,&inRecovery,&pid,&serverIP,&clientIP)
    if err!=nil||database!="fi"||user!="fi_ingest"||inRecovery||pid<=0||
        serverIP!=nil||clientIP!=nil{
        _=conn.Close(context.Background())
        return nil,0,fmt.Errorf("C1 fi-sor: rejected nonlocal, wrong-role, or standby PostgreSQL connection: %v",err)
    }
    return conn,pid,nil
}

// Instantiate C1's SAME ordered SourceParent writer and five shared SQL
// modules on fi-sor rather than in fi-ingest. Caller must first validate
// immutable signed batch metadata and private staging cleanliness.
func newC1SoRSQLPool(ctx context.Context,dsn,sourceID,generationID string,maxWorkers int)(*privateC1FiveSQL,error){
    if sourceID==""||generationID==""||maxWorkers<1||maxWorkers>32{
        return nil,errors.New("C1 fi-sor: original source and SQL worker limit required")
    }
    if _,err:=c1SoRLocalConnectionConfig(dsn);err!=nil{return nil,err}
    // The fi-sor C1 worker must never write partially committed rows into
    // the canonical fi schema or the discarded fi_recovery_projection stage.
    // The full signed-generation Bootstrap/verification path is still gated
    // until it is moved to this governed pending target.
    pool,err:=newC1SQLWithOpener(ctx,dsn,"",sourceID,maxWorkers,false,
        openC1SoRLocalSQL,false,c1GovernedPendingSchema)
    if err!=nil{return nil,err}
    // Assigned before any authenticated Source/Family dispatch. No SQL
    // worker uses this field before the first queued USN handoff.
    pool.usnGenerationID=generationID
    return pool,nil
}
