//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// C1 native B is a DISTINCT unprivileged fi-sor OS process with one
// independent local READ ONLY PostgreSQL session. A sends only original
// signed metadata and post-COMMIT group receipts; B cannot flush A or
// mutate fi_recovery or the populated canonical fi SoR.
package recordingest

import (
    "bufio"
    "context"
    "encoding/hex"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "os"
    "os/exec"
    "strconv"
    "strings"

    "github.com/Iron-Signal-Systems/fi/go/internal/c1handoff"
    "github.com/jackc/pgx/v5"
)

const c1NativeBPlanLimit=8<<20
type c1NativeBPlan struct {
    Start c1handoff.Frame
    SQLIDs []int64
    Batches []PreparedBatch
    Descriptors []BacklogCheckpointDescriptor
    Transfer string
    SQLSchema string // empty preserves the isolated private C1 benchmark
}
type c1SoRNativeB struct {
    cancel context.CancelFunc
    done chan struct{}
    err error // only written before closing done
}
// Schema is selected only by fi-sor's own frozen construction path.
func c1NativeBSchema(p c1NativeBPlan)(string,error){
    if p.SQLSchema==""||p.SQLSchema==privateProjectionSchema{
        return privateProjectionSchema,nil
    }
    if p.SQLSchema!=c1GovernedPendingSchema{
        return "",errors.New("C1 B: unapproved relational proof schema")
    }
    return c1GovernedPendingSchema,nil
}
func c1ValidateNativeBPlan(p c1NativeBPlan)error{
    if _,err:=c1NativeBSchema(p);err!=nil{return err}
    f:=p.Start
    if f.Kind!=c1handoff.Start||len(p.SQLIDs)==0||
        len(p.SQLIDs)!=len(f.BatchIDs)||len(p.Batches)!=len(f.BatchIDs)||
        len(p.Descriptors)<2||!canonicalDigest(p.Transfer)||f.ExpectedRecords<=0{
        return errors.New("C1 B: incomplete signed-generation verification plan")
    }
    if err:=f.Validate();err!=nil{return err}
    groups,err:=c1SoRGroupPlan(p.Batches,int(f.StartBatchIndex))
    if err!=nil{return err}
    if len(groups)+1!=len(p.Descriptors){return errors.New("C1 B: grouping changed")}
    seed:=p.Descriptors[0]
    if seed.EndBatch!=int(f.StartBatchIndex)||seed.EndRecord!=0||
        seed.SourceID!=f.SourceID||seed.GenerationID!=f.GenerationID||
        seed.ReceiptSHA256!=f.ReceiptSHA256||seed.TransferSHA256!=p.Transfer{
        return errors.New("C1 B: signed verified seed is not the precise group chain origin")
    }
    var total int64
    for i,g:=range groups{
        d:=p.Descriptors[i+1]
        prev:=p.Descriptors[i]
        if d.StartBatch!=g.firstBatch||d.EndBatch!=g.endBatch||
            d.StartBatch!=prev.EndBatch||
            d.StartRecord!=prev.EndRecord||
            d.EndRecord<=d.StartRecord||
            d.EndRecord-d.StartRecord!=uint64(g.count)||d.DataBytes!=uint64(g.bytes)||
            d.SourceID!=f.SourceID||d.GenerationID!=f.GenerationID||
            d.ReceiptSHA256!=f.ReceiptSHA256||d.TransferSHA256!=p.Transfer{
            return errors.New("C1 B: group metadata mismatches original manifest")
        }
        total+=g.count
    }
    if total!=f.ExpectedRecords||
        p.Descriptors[len(p.Descriptors)-1].EndRecord!=uint64(f.ExpectedRecords){
        return errors.New("C1 B: partial, discontinuous or changed signed group count")
    }
    for i,b:=range p.Batches{
        if p.SQLIDs[i]<=0||b.BatchID!=f.BatchIDs[i]||
            b.Manifest.RecordCount<=0||b.Manifest.DataBytes<=0||
            !canonicalDigest(b.ManifestSHA256)||!canonicalDigest(b.Manifest.DataSHA256){
            return errors.New("C1 B: incomplete original source batch identity")
        }
    }
    return nil
}

// B's receiver is independent of A's buffering. Even a stopped B cannot
// block one of the five P6 SQL lanes: the commit-ready channel has capacity
// for every original reporting group. Failure blocks ONLY final acceptance.
func startC1SoRNativeB(ctx context.Context,dsn string,p c1NativeBPlan,
    ready <-chan int,custody c1NativeBCustodyConfig)(*c1SoRNativeB,error){
    // The live fi-sor service ALWAYS execs its own installed worker with
    // exactly --c1-b-child. No transport-supplied command is permitted.
    return c1StartNativeBWithLauncher(ctx,dsn,p,ready,custody,
        func(own context.Context)(*exec.Cmd,error){
            exe,err:=os.Executable()
            if err!=nil{return nil,err}
            return exec.CommandContext(own,exe,"--c1-b-child"),nil
        })
}

// Private native FreeBSD CI seam: launch the same B parent IPC/scheduling
// engine with a test-binary child instead of the installed worker binary.
// Production calls ONLY the pinned launcher above. All input/READY/PASS/
// FINAL validation and independent B process checks are shared verbatim.
func c1StartNativeBWithLauncher(ctx context.Context,dsn string,p c1NativeBPlan,
    ready <-chan int,custody c1NativeBCustodyConfig,
    launch func(context.Context)(*exec.Cmd,error))(*c1SoRNativeB,error){
    if launch==nil{return nil,errors.New("C1 B: missing local child launcher")}
    if ctx==nil||dsn==""||ready==nil||custody.CustodyRoot==""||
        custody.RecordedRoot==""||custody.MaxCanonicalBytes==0||
        custody.MaxEncodedBytes==0||custody.MaxManifestBytes==0{
        return nil,errors.New("C1 B: missing signed custody verifier process inputs")
    }
    if err:=c1ValidateNativeBPlan(p);err!=nil{return nil,err}
    data,err:=json.Marshal(p)
    if err!=nil||len(data)==0||len(data)>c1NativeBPlanLimit{
        return nil,errors.New("C1 B: oversized signed plan IPC")
    }
    own,cancel:=context.WithCancel(ctx)
    cmd,err:=launch(own)
    if err!=nil{cancel();return nil,err}
    if cmd==nil{cancel();return nil,errors.New("C1 B: local child launcher returned no command")}
    if cmd.Env==nil{cmd.Env=os.Environ()}
    cmd.Env=append(cmd.Env,
        "FI_C1_B_CHILD=1","FI_C1_B_DSN="+dsn,
        "FI_C1_B_CUSTODY_ROOT="+custody.CustodyRoot,
        "FI_C1_B_RECORDED_ROOT="+custody.RecordedRoot,
        "FI_C1_B_SOURCE_NAMESPACES="+strconv.FormatBool(custody.SourceNamespaces),
        "FI_C1_B_MAX_CANONICAL="+strconv.FormatUint(custody.MaxCanonicalBytes,10),
        "FI_C1_B_MAX_ENCODED="+strconv.FormatUint(custody.MaxEncodedBytes,10),
        "FI_C1_B_MAX_MANIFEST="+strconv.FormatUint(custody.MaxManifestBytes,10),
    )
    cmd.Stderr=os.Stderr
    stdin,err:=cmd.StdinPipe()
    if err!=nil{cancel();return nil,err}
    stdout,err:=cmd.StdoutPipe()
    if err!=nil{cancel();_ =stdin.Close();return nil,err}
    if err=cmd.Start();err!=nil{cancel();_ =stdin.Close();return nil,err}
    v:=&c1SoRNativeB{cancel:cancel,done:make(chan struct{})}
    fmt.Printf("FI C1 NATIVE B OS PROCESS START pid=%d group_count=%d read_only=true\n",
        cmd.Process.Pid,len(p.Descriptors)-1)
    sent:=make(chan error,1)
    go func(){
        defer stdin.Close()
        if _,e:=stdin.Write(append(data,'\n'));e!=nil{sent<-e;return}
        for{
            select {
            case <-own.Done():sent<-own.Err();return
            case wi,ok:=<-ready:
                if !ok{_,e:=io.WriteString(stdin,"FINAL\n");sent<-e;return}
                if wi<1||wi>=len(p.Descriptors){sent<-errors.New("C1 B: unknown group");return}
                if _,e:=fmt.Fprintf(stdin,"READY %d\n",wi);e!=nil{sent<-e;return}
            }
        }
    }()
    go func(){
        scanner:=bufio.NewScanner(stdout)
        checked:=make(map[int]bool,len(p.Descriptors)-1)
        final:=false
        var scanErr error
        for scanner.Scan(){
            line:=scanner.Text()
            if line=="FINAL PASS"{
                if final||len(checked)!=len(p.Descriptors)-1{
                    scanErr=errors.New("C1 B: premature or duplicate final proof")
                    break
                }
                final=true
            }else if strings.HasPrefix(line,"PASS "){
                wi,e:=strconv.Atoi(strings.TrimPrefix(line,"PASS "))
                if e!=nil||wi<1||wi>=len(p.Descriptors)||checked[wi]||final{
                    scanErr=errors.New("C1 B: unrecognized or duplicate group proof")
                    break
                }
                checked[wi]=true
                fmt.Printf("FI C1 NATIVE B GROUP PROOF PASS group=%d separate_process=true read_only=true\n",wi)
            }else {
                scanErr=fmt.Errorf("C1 B: unexpected proof reply %q",line)
                break
            }
        }
        if scanErr==nil{scanErr=scanner.Err()}
        if scanErr!=nil||!final{cancel()}
        writerErr:=<-sent
        exitErr:=cmd.Wait()
        cancel()
        switch{
        case scanErr!=nil:v.err=scanErr
        case exitErr!=nil:v.err=fmt.Errorf("C1 B: process exited without complete proof: %w",exitErr)
        case writerErr!=nil:v.err=fmt.Errorf("C1 B: failed to send original commit receipts: %w",writerErr)
        case !final:v.err=errors.New("C1 B: complete relational proof missing")
        }
        if v.err!=nil{
            fmt.Printf("FI C1 NATIVE B FAILED error=%v acceptance=withheld ingest_cancelled=false\n",v.err)
        }else{
            fmt.Printf("FI C1 NATIVE B FULL RELATIONAL PROOF PASS groups=%d read_only=true independent_OS_process=true canonical_promotion=false\n",len(checked))
        }
        close(v.done)
    }()
    return v,nil
}
func(v *c1SoRNativeB)Finish(ctx context.Context)error{
    if v==nil||ctx==nil{return errors.New("C1 B: final verifier missing")}
    select{
    case <-ctx.Done():return ctx.Err()
    case <-v.done:return v.err
    }
}
func(v *c1SoRNativeB)Stop(){
    if v==nil{return}
    v.cancel()
    <-v.done
}

func RunC1SoRNativeBChild(ctx context.Context,input io.Reader,output io.Writer)error{
    // Production B ALWAYS loads its installed receiver trust; no IPC
    // frame, process environment or network peer can select a resolver.
    return c1RunNativeBChildWithTrust(ctx,input,output,loadInstalledGenerationTrust)
}

// Internal disposable FreeBSD acceptance seam. This does not weaken the
// production B child: only in-package tests can supply a separately signed
// isolated trust fixture. All B IPC, SQL and COMMIT-group checks remain the
// exact production code below.
func c1RunNativeBChildWithTrust(ctx context.Context,input io.Reader,
    output io.Writer,resolve generationTrustResolver)error{
    if resolve==nil{return errors.New("C1 B: original receiver trust resolver required")}
    if ctx==nil||input==nil||output==nil||os.Getenv("FI_C1_B_CHILD")!="1"{
        return errors.New("C1 B: separate process child authorization required")
    }
    dsn:=os.Getenv("FI_C1_B_DSN")
    if _,err:=c1SoRLocalConnectionConfig(dsn);err!=nil{return err}
    scan:=bufio.NewScanner(input)
    scan.Buffer(make([]byte,64<<10),c1NativeBPlanLimit)
    if !scan.Scan(){if e:=scan.Err();e!=nil{return e};return errors.New("C1 B: missing signed plan")}
    var p c1NativeBPlan
    if err:=json.Unmarshal(scan.Bytes(),&p);err!=nil{return err}
    if err:=c1ValidateNativeBPlan(p);err!=nil{return err}
    namespaces,err:=strconv.ParseBool(os.Getenv("FI_C1_B_SOURCE_NAMESPACES"))
    if err!=nil{return fmt.Errorf("C1 B: invalid original signed source namespaces: %w",err)}
    canonical,e:=strconv.ParseUint(os.Getenv("FI_C1_B_MAX_CANONICAL"),10,64)
    if e!=nil{return e}
    encoded,e:=strconv.ParseUint(os.Getenv("FI_C1_B_MAX_ENCODED"),10,64)
    if e!=nil{return e}
    manifest,e:=strconv.ParseUint(os.Getenv("FI_C1_B_MAX_MANIFEST"),10,64)
    if e!=nil{return e}
    custody:=c1NativeBCustodyConfig{
        CustodyRoot:os.Getenv("FI_C1_B_CUSTODY_ROOT"),
        RecordedRoot:os.Getenv("FI_C1_B_RECORDED_ROOT"),
        SourceNamespaces:namespaces,MaxCanonicalBytes:canonical,
        MaxEncodedBytes:encoded,MaxManifestBytes:manifest,
    }
    conn,pid,err:=openC1SoRLocalSQL(ctx,dsn,"")
    if err!=nil{return err}
    defer conn.Close(context.Background())
    if _,err=conn.Exec(ctx,"SET default_transaction_read_only=on");err!=nil{return err}
    if err=c1NativeBValidateStage(ctx,conn,p);err!=nil{return err}
    g:=&PreparedGeneration{Batches:p.Batches,ReceiptSHA256:p.Start.ReceiptSHA256}
    g.Receipt.TransferSHA256=p.Transfer
    g.Receipt.Descriptor.SourceID=p.Start.SourceID
    g.Receipt.Descriptor.GenerationID=p.Start.GenerationID
    seen:=make(map[int]bool,len(p.Descriptors)-1)
    fmt.Fprintf(os.Stderr,"FI C1 NATIVE B CHILD START pid=%d pg_pid=%d groups=%d\n",os.Getpid(),pid,len(p.Descriptors)-1)
    for scan.Scan(){
        line:=scan.Text()
        if line=="FINAL"{
            if len(seen)!=len(p.Descriptors)-1{return errors.New("C1 B: unverified groups at final gate")}
            if err:=c1NativeBCompleteRelational(ctx,conn,g,p);err!=nil{return err}
            if err:=c1NativeBVerifySignedCustodyWithTrust(ctx,conn,p,custody,resolve);err!=nil{
                return fmt.Errorf("C1 B: independent original signed custody and SQL readback: %w",err)
            }
            if _,err:=fmt.Fprintln(output,"FINAL PASS");err!=nil{return err}
            if scan.Scan(){return errors.New("C1 B: commands after final proof")}
            return scan.Err()
        }
        if !strings.HasPrefix(line,"READY "){return errors.New("C1 B: unrecognized command")}
        wi,e:=strconv.Atoi(strings.TrimPrefix(line,"READY "))
        if e!=nil||wi<1||wi>=len(p.Descriptors)||seen[wi]{
            return errors.New("C1 B: duplicate/invalid post-COMMIT group")
        }
        if err:=privateC1AsyncVerifyGroup(ctx,conn,g,p.Descriptors,wi,p.SQLSchema);err!=nil{
            return fmt.Errorf("C1 B: independent signed group %d: %w",wi,err)
        }
        seen[wi]=true
        if _,err:=fmt.Fprintf(output,"PASS %d\n",wi);err!=nil{return err}
    }
    if err:=scan.Err();err!=nil{return err}
    return errors.New("C1 B: missing final completion instruction")
}

func c1NativeBValidateStage(ctx context.Context,conn *pgx.Conn,p c1NativeBPlan)error{
    schema,err:=c1NativeBSchema(p)
    if err!=nil{return err}
    receipt,e:=hex.DecodeString(p.Start.ReceiptSHA256)
    if e!=nil{return e}
    var transfer []byte
    err=conn.QueryRow(ctx,"SELECT transfer_sha256 FROM "+pgx.Identifier{schema,"recorded_generation"}.Sanitize()+" WHERE source_id=$1 AND generation_id=$2 AND receipt_sha256=$3",
        p.Start.SourceID,p.Start.GenerationID,receipt).Scan(&transfer)
    if err!=nil||hex.EncodeToString(transfer)!=p.Transfer{
        return errors.New("C1 B: original transfer or receipt changed")
    }
    index:=make(map[int64]int,len(p.SQLIDs))
    for i,id:=range p.SQLIDs{
        if _,ok:=index[id];ok{return errors.New("C1 B: duplicate SQL batch identity")}
        index[id]=i
    }
    rows,err:=conn.Query(ctx,"SELECT source_batch_id,batch_id,record_count,data_bytes,manifest_sha256,data_sha256 FROM "+pgx.Identifier{schema,"source_batch"}.Sanitize()+" WHERE source_batch_id=ANY($1::bigint[])",p.SQLIDs)
    if err!=nil{return err}
    found:=0
    for rows.Next(){
        var id,n,size int64
        var batch string
        var manifest,data []byte
        if err=rows.Scan(&id,&batch,&n,&size,&manifest,&data);err!=nil{break}
        i,ok:=index[id]
        if !ok||batch!=p.Batches[i].BatchID||
            n!=int64(p.Batches[i].Manifest.RecordCount)||
            size!=p.Batches[i].Manifest.DataBytes||
            hex.EncodeToString(manifest)!=p.Batches[i].ManifestSHA256||
            hex.EncodeToString(data)!=p.Batches[i].Manifest.DataSHA256{
            err=errors.New("C1 B: original signed batch differs from independent SoR lookup")
            break
        }
        found++
    }
    if err==nil{err=rows.Err()}
    rows.Close()
    if err!=nil{return err}
    if found!=len(p.SQLIDs){return errors.New("C1 B: incomplete original signed batch ledger")}
    return nil
}

// This is a whole-generation relational proof on a populated database.
// It is NOT the separate original receiver source/artifact marker proof
// required before remapping into canonical fi or writing Accepted.
func c1NativeBCompleteRelational(ctx context.Context,conn *pgx.Conn,
    g *PreparedGeneration,p c1NativeBPlan)error{
    schema,err:=c1NativeBSchema(p)
    if err!=nil{return err}
    tx,err:=conn.BeginTx(ctx,pgx.TxOptions{IsoLevel:pgx.RepeatableRead,AccessMode:pgx.ReadOnly})
    if err!=nil{return err}
    defer tx.Rollback(context.Background())
    shadow:=privateProjectionTx{Tx:tx,schema:schema}
    id,ok,err:=lookupRecordedGeneration(ctx,shadow,
        p.Start.SourceID,p.Start.GenerationID,p.Transfer,p.Start.ReceiptSHA256)
    if err!=nil{return err}
    if !ok||id<=0{return errors.New("C1 B: final signed private generation unavailable")}
    var batches,records,bytes int64
    // The complete relational proof reads only the exact generation under
    // the approved fixed SQL schema; no dynamic frame-controlled SQL names.
    completeSQL:=strings.ReplaceAll("SELECT (SELECT count(*) FROM fi_recovery_projection.source_batch WHERE recorded_generation_id=$1),(SELECT count(*) FROM fi_recovery_projection.source_record r JOIN fi_recovery_projection.source_batch b USING(source_batch_id) WHERE b.recorded_generation_id=$1),(SELECT coalesce(sum(r.record_bytes),0)::bigint FROM fi_recovery_projection.source_record r JOIN fi_recovery_projection.source_batch b USING(source_batch_id) WHERE b.recorded_generation_id=$1)",
        privateProjectionSchema+".",schema+".")
    err=tx.QueryRow(ctx,completeSQL,id).
        Scan(&batches,&records,&bytes)
    if err!=nil{return err}
    var expectedRows,expectedBytes int64
    for _,batch:=range g.Batches{
        expectedRows+=int64(batch.Manifest.RecordCount)
        expectedBytes+=batch.Manifest.DataBytes
    }
    if batches!=int64(len(g.Batches))||records!=expectedRows||bytes!=expectedBytes{
        return errors.New("C1 B: complete private relational source totals differ from signed manifests")
    }
    if err=verifyGenerationProjectionCoverage(ctx,shadow,id);err!=nil{return err}
    if err=verifyBacklogUSNCapturesComplete(ctx,shadow,id);err!=nil{
        return fmt.Errorf("C1 B: original signed USN capture dependency proof: %w",err)
    }
    var authoritative bool
    if err=tx.QueryRow(ctx,"SELECT EXISTS(SELECT 1 FROM fi.recorded_generation WHERE source_id=$1 AND generation_id=$2)",
        p.Start.SourceID,p.Start.GenerationID).Scan(&authoritative);err!=nil{return err}
    if authoritative{return errors.New("C1 B: generation already canonical; do not republish")}
    return tx.Commit(ctx)
}
