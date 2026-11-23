// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// C1's fi-sor process receives SQL handoffs without serializing their
// PostgreSQL commits. The original shared SQL pool owns the actual commits,
// while this dispatcher emits an ACK for each original network sequence.
package c1handoff

import (
    "context"
    "errors"
    "fmt"
    "log"
    "net"
    "sync"
    "time"
)

type c1AckResult struct {
    frame Frame
    err error
}

// c1SQLRejectionDiagnostic is local-only. Never put this message or any
// underlying PostgreSQL text into the signed ACK's untrusted error field.
func c1SQLRejectionDiagnostic(source,generation string,f Frame,err error)string{
    return fmt.Sprintf(
        "FI C1 SOR SQL HANDOFF REJECTED source=%s generation=%s sequence=%d kind=%d cause=%v",
        source,generation,f.Sequence,f.Kind,err,
    )
}
func (s *Server)servePipelined(ctx context.Context,conn net.Conn,
    source,generation,receipt string,next uint64,idle time.Duration)(runErr error){
    if ctx==nil||conn==nil||s==nil||s.Dispatch==nil||s.Handler==nil||
        source==""||generation==""||receipt==""||next<2{
        return errors.New("C1 SQL pipeline: signed START and fi-sor handler required")
    }
    own,cancel:=context.WithCancel(ctx)
    defer cancel()
    permits:=make(chan struct{},MaxHandoffsInFlight)
    acknowledgments:=make(chan Frame,MaxHandoffsInFlight)
    writerErr:=make(chan error,1)
    // Sole socket writer. Independent SQL futures may commit out of order,
    // but no two TLS record writers may interleave their wire bytes.
    go func(){
        for ack:=range acknowledgments{
            if err:=conn.SetWriteDeadline(time.Now().Add(idle));err!=nil{
                writerErr<-err;_ =conn.Close();return
            }
            if err:=WriteFrame(conn,ack);err!=nil{
                writerErr<-err;_ =conn.Close();return
            }
        }
        writerErr<-nil
    }()
    var workers sync.WaitGroup
    defer func(){
        if runErr!=nil{cancel();_ =conn.Close()}
        workers.Wait()
        close(acknowledgments)
        if err:=<-writerErr;runErr==nil&&err!=nil{runErr=err}
    }()
    buildACK:=func(f Frame,err error)Frame{
        ack:=Frame{Kind:Ack,SourceID:source,GenerationID:generation,
            ReceiptSHA256:receipt,Sequence:f.Sequence,Committed:err==nil}
        if err!=nil{
            // The mTLS peer gets only a fixed rejection string. Preserve the
            // precise failure in the local fi-sor daemon log BEFORE sending
            // the NACK; the peer may immediately close the connection and
            // operators must never have to guess whether SQL or in-memory
            // admission rejected a high-volume signed buffer.
            log.Print(c1SQLRejectionDiagnostic(source,generation,f,err))
            ack.Error="FI C1 fi-sor SQL phase rejected this handoff"
        }
        return ack
    }
    for{
        if err:=own.Err();err!=nil{return err}
        // One bounded network admission credit per unacknowledged handoff.
        // The original P5/P6 producer sees backpressure at capacity.
        select{
        case permits<-struct{}{}:
        case <-own.Done():return own.Err()
        }
        if err:=conn.SetReadDeadline(time.Now().Add(idle));err!=nil{return err}
        frame,err:=ReadFrame(conn)
        if err!=nil{return err}
        if frame.Kind==Start||frame.Kind==Ack||
            frame.SourceID!=source||frame.GenerationID!=generation||
            frame.ReceiptSHA256!=receipt||frame.Sequence!=next{
            return errors.New("C1 SQL pipeline: duplicate, re-ordered or foreign signed request")
        }
        next++
        if frame.Kind==Drain{
            // ALL prior frames were handed to the native C1 SQL pool in
            // transport order; its WaitAll includes pending source/USN
            // dependencies. B continues verification in parallel.
            err=s.Handler(own,frame)
            // The handler waits for all SQL commit fences and independent
            // verification B. Only then can it expose a final proof.
            var proof FinalStatus
            if err==nil && s.FinalProof!=nil {
                proof,err=s.FinalProof(own,frame)
            }
            workers.Wait()
            ack:=buildACK(frame,err)
            if err==nil {ack.FinalStatus=proof}
            acknowledgments<-ack
            <-permits
            return err
        }
        if frame.Kind==Seal{
            // Signed reader group boundary is a notification only,
            // never a flush of Security/File/Coverage/USN/Other buffers.
            err=s.Handler(own,frame)
            acknowledgments<-buildACK(frame,err)
            <-permits
            if err!=nil{return fmt.Errorf("C1 SQL pipeline: invalid signed group seal: %w",err)}
            continue
        }
        if !isSQLKind(frame.Kind){
            return errors.New("C1 SQL pipeline: unknown typed source family")
        }
        future,err:=s.Dispatch(own,frame)
        if err!=nil{
            acknowledgments<-buildACK(frame,err)
            <-permits
            return fmt.Errorf("C1 SQL pipeline: native C1 SQL dispatch: %w",err)
        }
        if future==nil{return errors.New("C1 SQL pipeline: missing SQL COMMIT future")}
        workers.Add(1)
        go func(f Frame,done <-chan error){
            defer workers.Done()
            var result error
            select{
            case e,ok:=<-done:
                if !ok{
                    result=errors.New("C1 SQL pipeline: missing SQL completion result")
                }else{result=e}
            case <-own.Done():
                result=own.Err()
            }
            ack:=buildACK(f,result)
            select{
            case acknowledgments<-ack:
            case <-own.Done():
            }
            select{case <-permits:default:}
        }(frame,future)
    }
}
