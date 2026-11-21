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
    Descriptors []BacklogCheckpointDescriptor
    BatchIDs []string
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
        Descriptors:append([]BacklogCheckpointDescriptor(nil),ds[:end]...),
        BatchIDs:make([]string,ds[end-1].EndBatch),
    }
    for i:=range p.BatchIDs{p.BatchIDs[i]=g.Batches[i].BatchID}
    if err:=privateC1ValidateVerifyProcessPlan(&p);err!=nil{return p,err}
    return p,nil
}

func privateC1ValidateVerifyProcessPlan(p *privateC1VerifyProcessPlan)error{
    if p==nil||p.Version!="C1-B-1"||p.Start<1||p.End<=p.Start||
        p.End!=len(p.Descriptors)||p.SourceID==""||p.GenerationID==""||
        !canonicalDigest(p.ReceiptSHA256)||!canonicalDigest(p.TransferSHA256)||
        len(p.BatchIDs)==0||len(p.BatchIDs)!=p.Descriptors[p.End-1].EndBatch {
        return errors.New("FI C1 B: invalid bounded signed verification plan")
    }
    for i,id:=range p.BatchIDs{
        if id==""{return fmt.Errorf("FI C1 B: missing original batch ID %d",i)}
    }
    for i:=0;i<p.End;i++{
        d:=p.Descriptors[i]
        if d.SourceID!=p.SourceID||d.GenerationID!=p.GenerationID||
            d.ReceiptSHA256!=p.ReceiptSHA256||d.TransferSHA256!=p.TransferSHA256||
            d.StartBatch<0||d.EndBatch<=d.StartBatch||d.EndBatch>len(p.BatchIDs)||
            d.EndRecord<=d.StartRecord||d.DataBytes==0||
            p.BatchIDs[d.StartBatch]!=d.FirstBatchID||
            p.BatchIDs[d.EndBatch-1]!=d.LastBatchID {
            return fmt.Errorf("FI C1 B: changed or incomplete custody descriptor %d",i)
        }
        if i>0{
            prev:=p.Descriptors[i-1]
            if d.StartBatch!=prev.EndBatch||d.StartRecord!=prev.EndRecord||
                d.PreviousDigestSHA256!=prev.DigestSHA256{
                return fmt.Errorf("FI C1 B: discontinuous descriptor chain %d",i)
            }
        }
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
    drained chan struct{}
    markDrain sync.Once
    start,end int
    err error // written by waiter, read only after <-done
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
    if bin==""||!strings.HasPrefix(bin,"/home/jwood/fi-window-bench-w512-family-p3-"){
        return nil,errors.New("FI C1 B: exact private verifier executable path required")
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
    cmd.Stdout=os.Stdout
    cmd.Stderr=os.Stderr
    stdin,err:=cmd.StdinPipe()
    if err!=nil{cancel();return nil,err}
    if err=cmd.Start();err!=nil{cancel();_ =stdin.Close();return nil,err}
    v:=&privateC1ProcessVerifier{
        cmd:cmd,cancel:cancel,stdin:stdin,done:make(chan struct{}),
        drained:make(chan struct{}),start:start,end:end,
    }
    fmt.Printf("FI C1 B OS PROCESS SPAWN pid=%d groups=%d transport=bounded_stdin read_only=true controls_p6=false original_batch_sha_pass=none\n",
        cmd.Process.Pid,end-start)
    writerDone:=make(chan error,1)
    go func(){
        defer close(writerDone)
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
                    _,e:=io.WriteString(stdin,"FINISH\n")
                    writerDone<-e
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
        sendErr:=<-writerDone
        processErr:=cmd.Wait()
        if sendErr!=nil{
            v.err=fmt.Errorf("FI C1 B: transport: %w",sendErr)
        } else if processErr!=nil{
            v.err=fmt.Errorf("FI C1 B: independent process failed: %w",processErr)
        }
        if v.err!=nil&&onFailure!=nil{onFailure(v.err)}
        close(v.done)
    }()
    return v,nil
}

func(v *privateC1ProcessVerifier)MarkDrained(){
    if v!=nil{v.markDrain.Do(func(){close(v.drained)})}
}

func(v *privateC1ProcessVerifier)Finish(ctx context.Context)error{
    if v==nil||ctx==nil{return errors.New("FI C1 B: missing independent verifier")}
    v.MarkDrained()
    select{
    case <-ctx.Done():return ctx.Err()
    case <-v.done:
    }
    return v.err
}

func(v *privateC1ProcessVerifier)Stop(){
    if v==nil{return}
    v.cancel()
    _=v.stdin.Close()
    <-v.done
}

// The child protocol uses a single bounded input stream. No B-to-A command
// exists. B is read-only even if the database login has broader permissions.
func privateC1VerifyProcessCommands(ctx context.Context,scanner *bufio.Scanner,
    p *privateC1VerifyProcessPlan, check func(context.Context,int)error)error{
    if ctx==nil||scanner==nil||check==nil{return errors.New("FI C1 B: invalid verifier protocol")}
    if err:=privateC1ValidateVerifyProcessPlan(p);err!=nil{return err}
    expected:=p.Start
    drained:=false
    during:=0
    for scanner.Scan(){
        line:=scanner.Text()
        if line=="DRAIN"{
            if drained{return errors.New("FI C1 B: duplicate end-of-ingest signal")}
            drained=true
            continue
        }
        if line=="FINISH"{
            if expected!=p.End{
                return fmt.Errorf("FI C1 B: missing committed group %d",expected)
            }
            if scanner.Scan(){return errors.New("FI C1 B: commands after final proof")}
            if err:=scanner.Err();err!=nil{return err}
            fmt.Printf("FI C1 ASYNC VERIFY COMPLETE groups=%d during_ingest=%d after_drain=%d independent_read_only=true committed_ready=true original_relational_rescans=removed final_marker_gate=preserved separate_os_process=true\n",
                p.End-p.Start,during,p.End-p.Start-during)
            return nil
        }
        fields:=strings.Fields(line)
        if len(fields)!=2||fields[0]!="READY"{
            return errors.New("FI C1 B: unrecognized verifier command")
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
    return errors.New("FI C1 B: input closed before final committed-data proof")
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
    g:=&PreparedGeneration{ReceiptSHA256:p.ReceiptSHA256,Batches:make([]PreparedBatch,len(p.BatchIDs))}
    g.Receipt.TransferSHA256=p.TransferSHA256
    for i,id:=range p.BatchIDs{g.Batches[i].BatchID=id}
    fmt.Printf("FI C1 B OS PROCESS START pid=%d postgres_pid=%d groups=%d read_only=true separate_os_process=true\n",
        os.Getpid(),pid,p.End-p.Start)
    err=privateC1VerifyProcessCommands(ctx,scanner,&p,func(ctx context.Context,wi int)error{
        return privateC1AsyncVerifyGroup(ctx,conn,g,p.Descriptors,wi)
    })
    if err!=nil{
        fmt.Printf("FI C1 ASYNC VERIFY FAIL error=%v read_only=true fail_closed=true separate_os_process=true\n",err)
    }
    return err
}
