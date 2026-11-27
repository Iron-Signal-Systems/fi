//go:build freebsd && fi_c1_sor_dev && fi_c1_schema_pg_integration

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Native FreeBSD, disposable PostgreSQL18 ONLY. Re-execute the actual
// independent B SQL/receiver-custody verification code in a distinct OS
// PROCESS after the original signed mTLS/SQL phase. The child owns a
// different PostgreSQL session with default_transaction_read_only=on.
// This is an isolated test process, NOT the fi-sor production B child,
// not a second jail and not yet the parallel group-scheduler protocol.
package recordingest

import (
    "context"
    "crypto/x509"
    "encoding/json"
    "errors"
    "fmt"
    "os"
    "os/exec"
    "path/filepath"
    "strings"
    "testing"
    "time"

    "github.com/Iron-Signal-Systems/fi/go/internal/transporttrust"
    "github.com/jackc/pgx/v5"
)

type c1SignedBProcessFixture struct {
    Plan c1NativeBPlan
    Custody c1NativeBCustodyConfig
    RootDER []byte
    IssuerDER []byte
    CRLDER []byte
    Source transporttrust.SourceAuthorization
}

func c1TestRunIndependentSignedBProcess(ctx context.Context,t *testing.T,
    worker *pgx.Conn,p c1NativeBPlan,custody c1NativeBCustodyConfig,
    trust generationTrustBundle)error{
    t.Helper()
    if ctx==nil||worker==nil||os.Getenv("GITHUB_ACTIONS")!="true"||
        os.Getenv("FI_C1_SCHEMA_CI_ALLOW_DISPOSABLE")!="1"{
        return errors.New("C1 independent B: only disposable native FreeBSD authorized")
    }
    cfg:=worker.Config()
    if cfg.User!="fi_ingest"||cfg.Database!="fi"||cfg.Host!="127.0.0.1"||
        cfg.Port!=5432||cfg.Password!="isolated-only-test"||
        trust.Root==nil||trust.BatchIssuer==nil||trust.BatchCRL==nil{
        return errors.New("C1 independent B: unexpected worker SQL identity or original fixture trust")
    }
    if err:=c1ValidateNativeBPlan(p);err!=nil{return err}
    fixture:=c1SignedBProcessFixture{
        Plan:p,Custody:custody,
        RootDER:trust.Root.Raw,IssuerDER:trust.BatchIssuer.Raw,
        CRLDER:trust.BatchCRL.Raw,Source:trust.Source,
    }
    raw,err:=json.Marshal(fixture)
    if err!=nil{return err}
    file:=filepath.Join(t.TempDir(),"original-signed-b-fixture.json")
    if err=os.WriteFile(file,raw,0600);err!=nil{return err}
    executable,err:=os.Executable()
    if err!=nil{return err}
    // CI uses a fresh private PostgreSQL18 database and an ephemeral fixture
    // password. Do not pass this fixture DSN to fi-ingest or any real jail.
    dsn:=fmt.Sprintf("host=%s port=%d dbname=%s user=%s password=%s sslmode=disable",
        cfg.Host,cfg.Port,cfg.Database,cfg.User,cfg.Password)
    childCtx,cancel:=context.WithTimeout(ctx,30*time.Second)
    defer cancel()
    cmd:=exec.CommandContext(childCtx,executable,
        "-test.run=^TestC1IndependentSignedBProcessChild$","-test.v")
    cmd.Env=append(os.Environ(),
        "FI_C1_TEST_B_CHILD=1","FI_C1_TEST_B_FIXTURE="+file,
        "FI_C1_TEST_B_DSN="+dsn)
    output,err:=cmd.CombinedOutput()
    if err!=nil{
        return fmt.Errorf("C1 original signed B child process failed: %w\n%s",err,string(output))
    }
    if !strings.Contains(string(output),"PASS: independent FreeBSD B child verified"){
        return fmt.Errorf("C1 signed B child exited without positive original-custody proof:\n%s",string(output))
    }
    t.Log("PASS: independent original-custody B OS process confirmed with separate read-only PostgreSQL18 connection")
    return nil
}

// This test is not run by normal go test -run '^TestC1Private...$'; the
// parent launches ONLY this test with the signed fixture after real SQL
// COMMIT. No production trust paths are modified and there is no B bypass.
func TestC1IndependentSignedBProcessChild(t *testing.T){
    if os.Getenv("FI_C1_TEST_B_CHILD")!="1"{t.Skip("only an explicitly launched disposable FreeBSD B child")}
    if os.Getenv("GITHUB_ACTIONS")!="true"||
        os.Getenv("FI_C1_SCHEMA_CI_ALLOW_DISPOSABLE")!="1"{
        t.Fatal("C1 signed B child cannot run outside disposable FreeBSD CI")
    }
    path:=os.Getenv("FI_C1_TEST_B_FIXTURE")
    if !filepath.IsAbs(path)||strings.Contains(path,".."){
        t.Fatal("C1 signed B child fixture path must be isolated and absolute")
    }
    info,err:=os.Lstat(path)
    if err!=nil||!info.Mode().IsRegular()||info.Mode().Perm()!=0600{
        t.Fatalf("C1 signed B test fixture is not private regular material: %v",err)
    }
    raw,err:=os.ReadFile(path)
    if err!=nil{t.Fatal(err)}
    var fixture c1SignedBProcessFixture
    if err=json.Unmarshal(raw,&fixture);err!=nil{t.Fatal(err)}
    root,err:=x509.ParseCertificate(fixture.RootDER)
    if err!=nil{t.Fatal(err)}
    issuer,err:=x509.ParseCertificate(fixture.IssuerDER)
    if err!=nil{t.Fatal(err)}
    crl,err:=x509.ParseRevocationList(fixture.CRLDER)
    if err!=nil{t.Fatal(err)}
    p:=fixture.Plan
    if err=c1ValidateNativeBPlan(p);err!=nil{t.Fatal(err)}
    if p.SQLSchema!=c1GovernedPendingSchema{
        t.Fatal("C1 B child does not target the exact governed pending namespace")
    }
    trust:=func(source string)(generationTrustBundle,error){
        if source!=p.Start.SourceID||fixture.Source.SourceID!=source{
            return generationTrustBundle{},errors.New("C1 B child foreign receiver source trust")
        }
        return generationTrustBundle{
            Root:root,BatchIssuer:issuer,BatchCRL:crl,Source:fixture.Source,
        },nil
    }
    ctx,cancel:=context.WithTimeout(context.Background(),25*time.Second)
    defer cancel()
    conn,err:=pgx.Connect(ctx,os.Getenv("FI_C1_TEST_B_DSN"))
    if err!=nil{t.Fatal(err)}
    defer conn.Close(context.Background())
    var user,db string
    var standby bool
    if err=conn.QueryRow(ctx,`SELECT current_user,current_database(),pg_is_in_recovery()`).
        Scan(&user,&db,&standby);err!=nil{t.Fatal(err)}
    if user!="fi_ingest"||db!="fi"||standby{
        t.Fatal("C1 B child SQL identity not the disposable read-only verifier role")
    }
    if _,err=conn.Exec(ctx,"SET default_transaction_read_only = on");err!=nil{t.Fatal(err)}
    var ro string
    if err=conn.QueryRow(ctx,"SHOW default_transaction_read_only").Scan(&ro);err!=nil||ro!="on"{
        t.Fatal("C1 B child PostgreSQL session is not read-only")
    }
    g,err:=c1NativePromotionGeneration(p)
    if err!=nil{t.Fatal(err)}
    if err=c1NativeBValidateStage(ctx,conn,p);err!=nil{t.Fatal(err)}
    if err=c1NativeBCompleteRelational(ctx,conn,g,p);err!=nil{t.Fatal(err)}
    if err=c1NativeBVerifySignedCustodyWithTrust(ctx,conn,p,fixture.Custody,trust);err!=nil{
        t.Fatalf("C1 independent B original signed transfer / typed SQL mismatch: %v",err)
    }
    t.Log("PASS: independent FreeBSD B child verified complete original signed custody and committed relational SQL")
}
