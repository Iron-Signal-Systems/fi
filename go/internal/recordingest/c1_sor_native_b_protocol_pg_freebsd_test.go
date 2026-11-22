//go:build freebsd && fi_c1_sor_dev && fi_c1_schema_pg_integration

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Native disposable FreeBSD/PostgreSQL18 ONLY: execute the *actual* C1
// verifier B child input/READY/PASS/FINAL protocol in a separate test OS
// process using its own local Unix PostgreSQL session. Production retains
// fixed installed receiver trust; the private helper authenticates an
// ephemeral receiver-signed CI fixture instead. The C1 SQL writer, original
// custody and canonical publisher are unchanged.
package recordingest

import (
    "bytes"
    "context"
    "crypto/x509"
    "encoding/json"
    "errors"
    "fmt"
    "os"
    "os/exec"
    "path/filepath"
    "strconv"
    "strings"
    "testing"
    "time"

    "github.com/Iron-Signal-Systems/fi/go/internal/transporttrust"
    "github.com/jackc/pgx/v5"
)

type c1BReadyTrustFixture struct {
    RootDER []byte
    IssuerDER []byte
    CRLDER []byte
    Source transporttrust.SourceAuthorization
}

func c1TestNativeBReadyProtocol(t *testing.T,ctx context.Context,
    admin *pgx.Conn,p c1NativeBPlan,custody c1NativeBCustodyConfig,
    trust generationTrustBundle) {
    t.Helper()
    if os.Getenv("GITHUB_ACTIONS")!="true"||
        os.Getenv("FI_C1_SCHEMA_CI_ALLOW_DISPOSABLE")!="1"||
        admin==nil||trust.Root==nil||trust.BatchIssuer==nil||trust.BatchCRL==nil {
        t.Fatal("C1 B IPC: disposable signed FreeBSD PostgreSQL18 fixture required")
    }
    if err:=c1ValidateNativeBPlan(p);err!=nil{t.Fatal(err)}
    if p.SQLSchema!=c1GovernedPendingSchema||len(p.Descriptors)!=2{
        t.Fatal("C1 B IPC: exact one committed reporting group required")
    }
    var socketRoots string
    if err:=admin.QueryRow(ctx,"SHOW unix_socket_directories").Scan(&socketRoots);err!=nil{
        t.Fatal(err)
    }
    var socketDir string
    for _,candidate:=range strings.Split(socketRoots,",") {
        candidate=strings.TrimSpace(candidate)
        if !filepath.IsAbs(candidate){continue}
        if _,err:=os.Stat(filepath.Join(candidate,".s.PGSQL.5432"));err==nil{
            socketDir=candidate;break
        }
    }
    if socketDir==""{
        t.Fatalf("C1 B IPC: disposable PostgreSQL18 Unix socket missing from %q",socketRoots)
    }
    dsn:=fmt.Sprintf("host=%s port=5432 dbname=fi user=fi_ingest sslmode=disable",socketDir)
    if _,err:=c1SoRLocalConnectionConfig(dsn);err!=nil{t.Fatal(err)}
    trustFile:=filepath.Join(t.TempDir(),"c1-b-original-fixture.json")
    fixture:=c1BReadyTrustFixture{
        RootDER:trust.Root.Raw,IssuerDER:trust.BatchIssuer.Raw,
        CRLDER:trust.BatchCRL.Raw,Source:trust.Source,
    }
    raw,err:=json.Marshal(fixture)
    if err!=nil{t.Fatal(err)}
    if err=os.WriteFile(trustFile,raw,0600);err!=nil{t.Fatal(err)}
    plan,err:=json.Marshal(p)
    if err!=nil{t.Fatal(err)}
    exe,err:=os.Executable()
    if err!=nil{t.Fatal(err)}
    run:=func(commands string)(string,error){
        childCtx,cancel:=context.WithTimeout(ctx,25*time.Second)
        defer cancel()
        cmd:=exec.CommandContext(childCtx,exe,
            "-test.run=^TestC1ActualNativeBReadyProtocolChild$","-test.v")
        cmd.Stdin=bytes.NewReader(append(append(append([]byte{},plan...), '\n'),
            []byte(commands)...))
        cmd.Env=append(os.Environ(),
            "FI_C1_TEST_B_PROTOCOL_CHILD=1",
            "FI_C1_TEST_B_PROTOCOL_FIXTURE="+trustFile,
            "FI_C1_B_CHILD=1","FI_C1_B_DSN="+dsn,
            "FI_C1_B_CUSTODY_ROOT="+custody.CustodyRoot,
            "FI_C1_B_RECORDED_ROOT="+custody.RecordedRoot,
            "FI_C1_B_SOURCE_NAMESPACES="+strconv.FormatBool(custody.SourceNamespaces),
            "FI_C1_B_MAX_CANONICAL="+strconv.FormatUint(custody.MaxCanonicalBytes,10),
            "FI_C1_B_MAX_ENCODED="+strconv.FormatUint(custody.MaxEncodedBytes,10),
            "FI_C1_B_MAX_MANIFEST="+strconv.FormatUint(custody.MaxManifestBytes,10),
        )
        output,err:=cmd.CombinedOutput()
        return string(output),err
    }
    if output,err:=run("FINAL\n");err==nil||
        strings.Contains(output,"FINAL PASS"){
        t.Fatalf("C1 native B child accepted FINAL before durable SQL group READY: err=%v output=%s",err,output)
    }
    if output,err:=run("READY 1\nREADY 1\nFINAL\n");err==nil||
        strings.Contains(output,"FINAL PASS"){
        t.Fatalf("C1 native B child accepted duplicated commit-group notification: err=%v output=%s",err,output)
    }
    output,err:=run("READY 1\nFINAL\n")
    if err!=nil||!strings.Contains(output,"PASS 1")||
        !strings.Contains(output,"FINAL PASS") {
        t.Fatalf("C1 actual B OS child failed signed post-COMMIT READY/final protocol: err=%v output=%s",err,output)
    }
    // Drive the REAL B parent launcher/sender/scanner goroutines too.
    // The test binary child calls the same B proof engine, then exits
    // without the go-test PASS trailer (the production parent accepts
    // only strict "PASS n" and "FINAL PASS" protocol lines).
    ready:=make(chan int,1)
    verifier,err:=c1StartNativeBWithLauncher(ctx,dsn,p,ready,custody,
        func(own context.Context)(*exec.Cmd,error){
            child:=exec.CommandContext(own,exe,
                "-test.run=^TestC1ActualNativeBReadyProtocolChild$")
            child.Env=append(os.Environ(),
                "FI_C1_TEST_B_PROTOCOL_CHILD=1",
                "FI_C1_TEST_B_PROTOCOL_FIXTURE="+trustFile,
                "FI_C1_TEST_B_DIRECT_IO=1")
            return child,nil
        })
    if err!=nil{t.Fatalf("C1 B real parent worker process could not start: %v",err)}
    ready<-1
    close(ready)
    if err=verifier.Finish(ctx);err!=nil{
        verifier.Stop()
        t.Fatalf("C1 real parent/child post-COMMIT notification/ACK protocol failed: %v",err)
    }
    t.Log("PASS: actual C1 B child and its parent launcher/notification goroutines completed the strict signed post-COMMIT READY/PASS/FINAL protocol")
}

// Invoked only with the exact name above in a separate FreeBSD test OS
// process. The only test seam is trust resolved from private signed fixture
// material; the real C1 B IPC/SQL/verification logic remains unchanged.
func TestC1ActualNativeBReadyProtocolChild(t *testing.T){
    if os.Getenv("FI_C1_TEST_B_PROTOCOL_CHILD")!="1"{
        t.Skip("not a disposable native B IPC child")
    }
    if os.Getenv("GITHUB_ACTIONS")!="true"||
        os.Getenv("FI_C1_SCHEMA_CI_ALLOW_DISPOSABLE")!="1"{
        t.Fatal("C1 native B IPC child outside isolated FreeBSD CI")
    }
    path:=os.Getenv("FI_C1_TEST_B_PROTOCOL_FIXTURE")
    if !filepath.IsAbs(path)||strings.Contains(path,".."){
        t.Fatal("C1 B IPC unapproved fixture path")
    }
    info,err:=os.Lstat(path)
    if err!=nil||!info.Mode().IsRegular()||info.Mode().Perm()!=0600{
        t.Fatalf("C1 B IPC fixture material is not protected: %v",err)
    }
    raw,err:=os.ReadFile(path)
    if err!=nil{t.Fatal(err)}
    var f c1BReadyTrustFixture
    if err=json.Unmarshal(raw,&f);err!=nil{t.Fatal(err)}
    root,err:=x509.ParseCertificate(f.RootDER)
    if err!=nil{t.Fatal(err)}
    issuer,err:=x509.ParseCertificate(f.IssuerDER)
    if err!=nil{t.Fatal(err)}
    crl,err:=x509.ParseRevocationList(f.CRLDER)
    if err!=nil{t.Fatal(err)}
    trust:=func(source string)(generationTrustBundle,error){
        if source!=f.Source.SourceID {
            return generationTrustBundle{},errors.New("C1 native B IPC foreign receiver trust")
        }
        return generationTrustBundle{
            Root:root,BatchIssuer:issuer,BatchCRL:crl,Source:f.Source,
        },nil
    }
    ctx,cancel:=context.WithTimeout(context.Background(),20*time.Second)
    defer cancel()
    if err:=c1RunNativeBChildWithTrust(ctx,os.Stdin,os.Stdout,trust);err!=nil{
        if os.Getenv("FI_C1_TEST_B_DIRECT_IO")=="1"{
            fmt.Fprintln(os.Stderr,err)
            os.Exit(1)
        }
        t.Fatal(err)
    }
    if os.Getenv("FI_C1_TEST_B_DIRECT_IO")=="1" {
        // Suppress the test runner's unconditional PASS output. The actual
        // production parent rejects any unrecognized child stdout line.
        os.Exit(0)
    }
}
