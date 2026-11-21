// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Clone-only C1 A/B: B runs as an independent operating-system process.
// Its bounded, one-way pipe receives *only* metadata for receiver-custodied
// groups and COMMIT-ready notifications. B never writes to A's SQL coordinator,
// controls a P6 buffer, or recalculates original source-batch SHA-256.
package recordingest

import (
    "bufio"
    "bytes"
    "context"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "os"
    "os/exec"
    "path/filepath"
    "strconv"
    "strings"
    "sync"
    "time"
)

const privateC1VerifyPlanMaxBytes = 4 << 20

// The plan carries existing custody identities and exact original batch IDs,
// not source records, new custody artifacts, or any hashes to recompute.
type privateC1VerifyProcessPlan struct {
    Version string
    SourceID string
    GenerationID string
    TransferSHA256 string
    ReceiptSHA256 string
    Start int
    End int
    TotalRecords uint64
    TotalBytes uint64
    Descriptors []BacklogCheckpointDescriptor
    BatchIDs []string
    BatchRecords []int
    BatchBytes []int64
}

func privateC1BuildVerifyProcessPlan(g *PreparedGeneration, ds []BacklogCheckpointDescriptor,
    start,end int)(privateC1VerifyProcessPlan,error){
    var p privateC1VerifyProcessPlan
    if g==nil||start<1||end<=start||end>len(ds)||
        ds[end-1].EndBatch>len(g.Batches){
        return p,errors.New("FI C1 B: invalid custody descriptor range")
    }
    p=privateC1VerifyProcessPlan{
        Version:"C1-B-1",
        SourceID:ds[0].SourceID,GenerationID:ds[0].GenerationID,
        TransferSHA256:g.Receipt.TransferSHA256,
        ReceiptSHA256:g.ReceiptSHA256,
        Start:start,End:end,
        TotalRecords:g.Receipt.RecordCount,TotalBytes:g.Receipt.DataBytes,
        Descriptors:append([]BacklogCheckpointDescriptor(nil),ds...),
        BatchIDs:make([]string,len(g.Batches)),
        BatchRecords:make([]int,len(g.Batches)),
        BatchBytes:make([]int64,len(g.Batches)),
    }
    for i:=range p.BatchIDs{
        p.BatchIDs[i]=g.Batches[i].BatchID
        p.BatchRecords[i]=g.Batches[i].Manifest.RecordCount
        p.BatchBytes[i]=g.Batches[i].Manifest.DataBytes
    }
    if err:=privateC1ValidateVerifyProcessPlan(&p);err!=nil{return p,err}
    return p,nil
}

func privateC1ValidateVerifyProcessPlan(p *privateC1VerifyProcessPlan)error{
    if p==nil||p.Version!="C1-B-1"||p.Start<1||p.End<=p.Start||
        p.End>len(p.Descriptors)||p.SourceID==""||p.GenerationID==""||
        !canonicalDigest(p.ReceiptSHA256)||!canonicalDigest(p.TransferSHA256)||
        p.TotalRecords==0||p.TotalBytes==0||
        len(p.BatchIDs)==0||len(p.BatchIDs)!=p.Descriptors[len(p.Descriptors)-1].EndBatch||
        len(p.BatchIDs)!=len(p.BatchRecords)||len(p.BatchIDs)!=len(p.BatchBytes)||
        p.Descriptors[len(p.Descriptors)-1].EndRecord!=p.TotalRecords {
        return errors.New("FI C1 B: invalid bounded signed verification plan")
    }
    var totalBatchBytes uint64
    var totalBatchRecords uint64
    for i,id:=range p.BatchIDs{
        if id==""||p.BatchRecords[i]<=0||p.BatchBytes[i]<=0{
            return fmt.Errorf("FI C1 B: missing original batch identity/size %d",i)
        }
        totalBatchBytes+=uint64(p.BatchBytes[i])
        totalBatchRecords+=uint64(p.BatchRecords[i])
    }
    if totalBatchBytes!=p.TotalBytes||totalBatchRecords!=p.TotalRecords{
        return errors.New("FI C1 B: custody metadata does not sum to original signed receipt")
    }
    var totalDescriptorBytes uint64
    for i:=0;i<len(p.Descriptors);i++{
        d:=p.Descriptors[i]
        if d.SourceID!=p.SourceID||d.GenerationID!=p.GenerationID||
            d.ReceiptSHA256!=p.ReceiptSHA256||d.TransferSHA256!=p.TransferSHA256||
            d.StartBatch<0||d.EndBatch<=d.StartBatch||d.EndBatch>len(p.BatchIDs)||
            d.EndRecord<=d.StartRecord||d.DataBytes==0||
            p.BatchIDs[d.StartBatch]!=d.FirstBatchID||
            p.BatchIDs[d.EndBatch-1]!=d.LastBatchID {
            return fmt.Errorf("FI C1 B: changed or incomplete custody descriptor %d",i)
        }
        totalDescriptorBytes+=d.DataBytes
        if i>0{
            prev:=p.Descriptors[i-1]
            if d.StartBatch!=prev.EndBatch||d.StartRecord!=prev.EndRecord||
                d.PreviousDigestSHA256!=prev.DigestSHA256{
                return fmt.Errorf("FI C1 B: discontinuous descriptor chain %d",i)
            }
        }
    }
    if totalDescriptorBytes!=p.TotalBytes{
        return errors.New("FI C1 B: group byte total differs from original custody receipt")
    }
    return nil
}

// A owns the pipe writer; B only consumes committed-data notifications.
// The 16-group bounded queue prevents slow B SQL queries from backpressuring
// A's five P6 lanes or shared PostgreSQL workers.
type privateC1ProcessVerifier struct {
    cancel context.CancelFunc
    cmd *exec.Cmd
    stdin io.WriteCloser
    done chan struct{}
    groupsDone chan struct{}
    finish chan struct{}
    drained chan struct{}
    markDrain sync.Once
    ackGroups sync.Once
    markFinal sync.Once
    start,end int
    result BacklogGenerationVerification // stdout scanner-owned, read after <-done
    gotFinal bool
    err error // waiter-owned, read after <-done
}

func privateC1StartProcessVerify(ctx context.Context,dsn,pgdata string,
    g *PreparedGeneration,ds []BacklogCheckpointDescriptor,start,end int,
    ready <-chan int,onFailure func(error),
)(*privateC1ProcessVerifier,error){
    if ctx==nil||ready==nil||!privateC1Enabled()||
        os.Getenv("FI_C1_DEV_ASYNC_VERIFY")!="1"||
        os.Getenv("FI_C1_DEV_PROCESS_VERIFY")!="1"||
        dsn==""||pgdata==""{
        return nil,errors.New("FI C1 B: independent process is permitted only on the selected private clone")
    }
    bin:=os.Getenv("FI_C1_DEV_VERIFIER_BIN")
    // A executes on the C220 host, but both Go binaries are built in fi-dev.
    // Require B to be the host-visible executable in the exact same private
    // run directory as the verified jail-relative PostgreSQL clone.
    expectedInside:=filepath.Join(filepath.Dir(filepath.Dir(pgdata)),"fi-c1-verifier")
    expectedHost:="/fast/jails/roots/fi-dev"+expectedInside
    if bin==""||bin!=expectedHost||
        !strings.HasPrefix(expectedInside,"/home/jwood/fi-window-bench-w512-family-p3-"){
        return nil,errors.New("FI C1 B: verifier path must match the host-visible private clone executable")
    }
    st,err:=os.Stat(bin)
    if err!=nil||!st.Mode().IsRegular()||st.Mode()&0111==0{
        return nil,errors.New("FI C1 B: private verifier executable unavailable")
    }
    plan,err:=privateC1BuildVerifyProcessPlan(g,ds,start,end)
    if err!=nil{return nil,err}
    payload,err:=json.Marshal(plan)
    if err!=nil||len(payload)==0||len(payload)>privateC1VerifyPlanMaxBytes{
        return nil,errors.New("FI C1 B: custody verification plan exceeds fixed bound")
    }
    childCtx,cancel:=context.WithCancel(ctx)
    cmd:=exec.CommandContext(childCtx,bin)
    cmd.Env=append(os.Environ(),"FI_C1_DEV_VERIFY_CHILD=1")
    cmd.Stderr=os.Stderr
    stdout,err:=cmd.StdoutPipe()
    if err!=nil{cancel();return nil,err}
    stdin,err:=cmd.StdinPipe()
    if err!=nil{cancel();return nil,err}
    if err=cmd.Start();err!=nil{cancel();_ =stdin.Close();return nil,err}
    v:=&privateC1ProcessVerifier{
        cmd:cmd,cancel:cancel,stdin:stdin,done:make(chan struct{}),
        groupsDone:make(chan struct{}),finish:make(chan struct{}),
        drained:make(chan struct{}),start:start,end:end,
    }
    fmt.Printf("FI C1 B OS PROCESS SPAWN pid=%d parent_pid=%d groups=%d transport=bounded_stdin read_only=true controls_p6=false original_batch_sha_pass=none\n",
        cmd.Process.Pid,os.Getpid(),end-start)
    // B's stdout is a receipt-only response channel. Its usual diagnostics
    // are relayed unchanged to the existing C220 transcript.
    stdoutDone:=make(chan error,1)
    go func(){
        scanner:=bufio.NewScanner(stdout)
        scanner.Buffer(make([]byte,64<<10),privateC1VerifyPlanMaxBytes)
        for scanner.Scan(){
            line:=scanner.Text()
            fmt.Println(line)
            if strings.HasPrefix(line,"FI C1 B GROUPS PROOF PASS "){
                v.ackGroups.Do(func(){close(v.groupsDone)})
            }
            const prefix="FI C1 B FINAL RESULT "
            if strings.HasPrefix(line,prefix){
                if e:=json.Unmarshal([]byte(strings.TrimPrefix(line,prefix)),&v.result);e!=nil{
                    stdoutDone<-fmt.Errorf("FI C1 B: invalid final result: %w",e)
                    return
                }
                v.gotFinal=true
            }
        }
        stdoutDone<-scanner.Err()
    }()
    writerDone:=make(chan error,1)
    go func(){
        defer stdin.Close()
        if _,e:=stdin.Write(append(payload,'\n'));e!=nil{
            writerDone<-fmt.Errorf("FI C1 B: send custody plan: %w",e)
            return
        }
        drain:=v.drained
        for{
            select{
            case <-childCtx.Done():
                writerDone<-childCtx.Err()
                return
            case <-drain:
                if _,e:=io.WriteString(stdin,"DRAIN\n");e!=nil{
                    writerDone<-e
                    return
                }
                drain=nil
            case wi,ok:=<-ready:
                if !ok{
                    // Drain notification must precede the final group seal
                    // even when the ready queue wins the select repeatedly.
                    if drain!=nil{
                        if _,e:=io.WriteString(stdin,"DRAIN\n");e!=nil{
                            writerDone<-e
                            return
                        }
                        drain=nil
                    }
                    if _,e:=io.WriteString(stdin,"GROUPS\n");e!=nil{
                        writerDone<-e
                        return
                    }
                    select{
                    case <-childCtx.Done():
                        writerDone<-childCtx.Err()
                    case <-v.finish:
                        _,e:=io.WriteString(stdin,"FINAL\n")
                        writerDone<-e
                    }
                    return
                }
                if wi<start||wi>=end{
                    writerDone<-fmt.Errorf("FI C1 B: invalid commit-ready group %d",wi)
                    return
                }
                if _,e:=fmt.Fprintf(stdin,"READY %d\n",wi);e!=nil{
                    writerDone<-e
                    return
                }
            }
        }
    }()
    go func(){
        // Reader EOF also occurs when B crashes before sending GROUPS.
        // Cancel only the child context so the sender cannot strand A.
        scanErr:=<-stdoutDone
        cancel()
        sendErr:=<-writerDone
        processErr:=cmd.Wait()
        if sendErr!=nil{
            v.err=fmt.Errorf("FI C1 B: transport: %w",sendErr)
        }else if processErr!=nil{
            v.err=fmt.Errorf("FI C1 B: independent process failed: %w",processErr)
        }else if scanErr!=nil{
            v.err=fmt.Errorf("FI C1 B: receipt read: %w",scanErr)
        }else if !v.gotFinal{
            v.err=errors.New("FI C1 B: final process proof receipt missing")
        }
        if v.err!=nil&&onFailure!=nil{onFailure(v.err)}
        close(v.done)
    }()
    return v,nil
}

func(v *privateC1ProcessVerifier)MarkDrained(){
    if v!=nil{v.markDrain.Do(func(){close(v.drained)})}
}

// Group proofs must pass BEFORE A may write its private typed markers.
// A's P5/P6 work has already committed; B never controls those buffers.
func(v *privateC1ProcessVerifier)WaitGroups(ctx context.Context)error{
    if v==nil||ctx==nil{return errors.New("FI C1 B: missing independent group verifier")}
    v.MarkDrained()
    select{
    case <-ctx.Done():return ctx.Err()
    case <-v.done:
        if v.err!=nil{return v.err}
        return errors.New("FI C1 B: exited without committed group proofs")
    case <-v.groupsDone:
        return nil
    }
}

// After A writes private typed markers, the SAME B OS process completes the
// final read-only proof. No Accepted or authoritative mutation is permitted.
func(v *privateC1ProcessVerifier)Finish(ctx context.Context)(BacklogGenerationVerification,error){
    var empty BacklogGenerationVerification
    if v==nil||ctx==nil{return empty,errors.New("FI C1 B: missing final proof")}
    v.markFinal.Do(func(){close(v.finish)})
    select{
    case <-ctx.Done():return empty,ctx.Err()
    case <-v.done:
    }
    if v.err!=nil{return empty,v.err}
    if !v.gotFinal{return empty,errors.New("FI C1 B: final proof receipt was absent")}
    return v.result,nil
}

func(v *privateC1ProcessVerifier)Stop(){
    if v==nil{return}
    v.cancel()
    _=v.stdin.Close()
    <-v.done
}

// The independent child accepts only original custody metadata and ordered
// durable SQL-ready events. It returns a small GROUPS proof receipt, then
// waits for A's private marker COMMIT before the final read-only proof.
func privateC1VerifyProcessCommands(ctx context.Context,scanner *bufio.Scanner,
    p *privateC1VerifyProcessPlan,check func(context.Context,int)error,
    final func(context.Context)(BacklogGenerationVerification,error))error{
    if ctx==nil||scanner==nil||check==nil||final==nil{
        return errors.New("FI C1 B: invalid verifier protocol")
    }
    if err:=privateC1ValidateVerifyProcessPlan(p);err!=nil{return err}
    expected:=p.Start
    drained:=false
    during:=0
    groupsAck:=false
    for scanner.Scan(){
        line:=scanner.Text()
        if line=="DRAIN"{
            if drained||groupsAck{
                return errors.New("FI C1 B: duplicate or late end-of-ingest signal")
            }
            drained=true
            continue
        }
        if line=="GROUPS"{
            if !drained||groupsAck||expected!=p.End{
                return fmt.Errorf("FI C1 B: incomplete or duplicate group proof expected=%d end=%d",expected,p.End)
            }
            groupsAck=true
            fmt.Printf("FI C1 ASYNC VERIFY COMPLETE groups=%d during_ingest=%d after_drain=%d independent_read_only=true committed_ready=true original_relational_rescans=removed final_marker_gate=preserved separate_os_process=true\n",
                p.End-p.Start,during,p.End-p.Start-during)
            fmt.Printf("FI C1 B GROUPS PROOF PASS groups=%d read_only=true no_p6_flush=true awaiting_final_marker=true\n",
                p.End-p.Start)
            continue
        }
        if line=="FINAL"{
            if !groupsAck{
                return errors.New("FI C1 B: final generation proof before committed group acknowledgement")
            }
            began:=time.Now()
            result,err:=final(ctx)
            if err!=nil{return fmt.Errorf("FI C1 B: final generation proof: %w",err)}
            mode:="prefix"
            if p.End==len(p.Descriptors){mode="generation"}
            fmt.Printf("FI C1 B FINAL GENERATION VERIFY PASS mode=%s groups=%d duration=%s read_only=true separate_os_process=true\n",
                mode,p.End-p.Start,time.Since(began))
            encoded,err:=json.Marshal(result)
            if err!=nil{return fmt.Errorf("FI C1 B: final receipt encode: %w",err)}
            fmt.Printf("FI C1 B FINAL RESULT %s\n",encoded)
            if scanner.Scan(){return errors.New("FI C1 B: commands after final proof")}
            if err:=scanner.Err();err!=nil{return err}
            return nil
        }
        fields:=strings.Fields(line)
        if len(fields)!=2||fields[0]!="READY"||groupsAck{
            return errors.New("FI C1 B: unexpected verifier command or readiness after group seal")
        }
        wi,e:=strconv.Atoi(fields[1])
        if e!=nil||wi!=expected{
            return fmt.Errorf("FI C1 B: duplicate, skipped or unordered group %q expected=%d",fields[1],expected)
        }
        began:=time.Now()
        if e=check(ctx,wi);e!=nil{
            return fmt.Errorf("FI C1 B: group %d independent relational proof: %w",wi,e)
        }
        phase:="during_ingest"
        if drained{phase="after_drain"}else{during++}
        fmt.Printf("FI C1 ASYNC VERIFY PASS window=%d attempts=1 phase=%s duration=%s read_only=true independent_connection=true commit_ready=true separate_os_process=true\n",
            wi,phase,time.Since(began))
        expected++
    }
    if err:=scanner.Err();err!=nil{return err}
    return errors.New("FI C1 B: input closed before final independent generation proof")
}

// RunPrivateC1VerifyChild is exported only so the PRIVATE, separately built
// verifier executable can call the same original relational proof. The child
// does not load custody files or source batches; A sends original IDs only.
func RunPrivateC1VerifyChild(ctx context.Context,input io.Reader)error{
    if ctx==nil||input==nil||
        os.Getenv("FI_C1_DEV_VERIFY_CHILD")!="1"||
        os.Getenv("FI_C1_DEV_PROCESS_VERIFY")!="1"||
        !privateC1Enabled(){
        return errors.New("FI C1 B: child forbidden outside private C1 experiment")
    }
    scanner:=bufio.NewScanner(input)
    scanner.Buffer(make([]byte,64<<10),privateC1VerifyPlanMaxBytes)
    if !scanner.Scan(){
        if err:=scanner.Err();err!=nil{return err}
        return errors.New("FI C1 B: absent sender custody plan")
    }
    var p privateC1VerifyProcessPlan
    if err:=json.Unmarshal(bytes.TrimSpace(scanner.Bytes()),&p);err!=nil{return err}
    if err:=privateC1ValidateVerifyProcessPlan(&p);err!=nil{return err}
    dsn,pgdata:=os.Getenv("FI_W512_C1_SQL_DSN"),os.Getenv("FI_W512_C1_EXPECTED_PGDATA")
    conn,pid,err:=privateC1CloneConnection(ctx,dsn,pgdata)
    if err!=nil{return err}
    defer conn.Close(context.Background())
    if _,err=conn.Exec(ctx,"SET default_transaction_read_only = on");err!=nil{return err}
    // B receives only existing signed-receipt metadata, not raw source data.
    // Reconstruct the exact count/byte descriptors required by FI's existing
    // prefix and complete-generation relational SQL proof functions.
    g:=&PreparedGeneration{ReceiptSHA256:p.ReceiptSHA256,Batches:make([]PreparedBatch,len(p.BatchIDs))}
    g.Receipt.TransferSHA256=p.TransferSHA256
    g.Receipt.Descriptor.SourceID=p.SourceID
    g.Receipt.Descriptor.GenerationID=p.GenerationID
    g.Receipt.BatchCount=uint64(len(p.BatchIDs))
    g.Receipt.RecordCount=p.TotalRecords
    g.Receipt.DataBytes=p.TotalBytes
    for i,id:=range p.BatchIDs{
        g.Batches[i].BatchID=id
        g.Batches[i].Manifest.RecordCount=p.BatchRecords[i]
        g.Batches[i].Manifest.DataBytes=p.BatchBytes[i]
    }
    fmt.Printf("FI C1 B OS PROCESS START pid=%d postgres_pid=%d groups=%d read_only=true separate_os_process=true\n",
        os.Getpid(),pid,p.End-p.Start)
    err=privateC1VerifyProcessCommands(ctx,scanner,&p,func(ctx context.Context,wi int)error{
        return privateC1AsyncVerifyGroup(ctx,conn,g,p.Descriptors,wi)
    },func(ctx context.Context)(BacklogGenerationVerification,error){
        if p.End<len(p.Descriptors){
            var empty BacklogGenerationVerification
            if err:=privateC1VerifyEightGiBPrefix(ctx,conn,g,p.Descriptors,p.End);err!=nil{
                return empty,err
            }
            return empty,nil
        }
        return privateC1VerifyCompleteGroupedReplay(ctx,conn,g,p.Descriptors)
    })
    if err!=nil{
        fmt.Printf("FI C1 ASYNC VERIFY FAIL error=%v read_only=true fail_closed=true separate_os_process=true\n",err)
    }
    return err
}
