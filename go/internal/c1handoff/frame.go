// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// The C1 phase boundary is an authenticated, bounded handoff. FI ingest
// prepares signed rows; FI SoR alone executes the ordered PostgreSQL parent
// writer and the five adaptive SQL family modules. No package here opens SQL.
package c1handoff

import (
    "bytes"
    "crypto/sha256"
    "crypto/subtle"
    "encoding/binary"
    "encoding/hex"
    "errors"
    "fmt"
    "io"
    "strings"
)

const (
    MaxRows = 8192
    // Every original signed JSONL batch is capped at 64 MiB. One
    // individual signed record cannot legally exceed its own batch.
    MaxSingleRecordBytes = 64 << 20
    MaxPayloadBytes = (64 << 20) + (8 << 20)
    maxText = 1024
    maxError = 4096
)
// The final-proof marker changes the binary wire format. Reject a mixed
// build rather than silently reading an old SQL ACK as canonical acceptance.
var magic = [8]byte{'F','I','C','1','H','N','D','2'}

// FinalStatus differentiates a durable SQL phase ACK from B's independent
// original-custody proof and a real canonical Accepted transaction.
// Verified NEVER means published, and only Accepted authorizes a receiver
// generation-complete acknowledgment.
type FinalStatus uint8
const (
    FinalNone FinalStatus = iota
    FinalVerified
    FinalAccepted
)

type Kind uint8
const (
    Source Kind = 1
    Security Kind = 2
    File Kind = 3
    Coverage Kind = 4
    USN Kind = 5
    Other Kind = 6
    Drain Kind = 7
    Ack Kind = 8
    Start Kind = 9
    Seal Kind = 10
    // An initial, read-only, authenticated canonical acceptance probe.
    // Status is never an ingest SQL phase and never carries RAM objects.
    Status Kind = 11
)

type Row struct {
    SignedBatchIndex uint32
    SourceBatchID int64
    Ordinal int64
    RawRecord []byte
    Digest [32]byte
}
type Frame struct {
    Kind Kind
    SourceID string
    GenerationID string
    ReceiptSHA256 string
    Sequence uint64
    Rows []Row
    // SQL work may instead reference an immutable prepared buffer in
    // host tmpfs, nullfs-mounted read-only into fi-sor. The mTLS frame
    // authenticates its exact name, byte length, row count and SHA-256.
    Shared SharedRAMRef
    // Start exchanges immutable signed batch names for validated SQL IDs.
    // It never moves PostgreSQL connections or SQL work into fi-ingest.
    BatchIDs []string
    BatchSQLIDs []int64 // Only the fi-sor START acknowledgment carries these.
    ExpectedRecords int64
    StartBatchIndex uint32 // first signed batch not already in verified seed
    SealedGroup uint32 // Seal never flushes any SQL family buffer
    // Acknowledgments are emitted only after durable SQL COMMIT.
    Committed bool
    Error string
    // Only final Drain ACK may carry an independent B proof or canonical
    // Accepted result. Every Source/Family/Seal/Start ACK is SQL-only.
    FinalStatus FinalStatus
}

func isSQLKind(kind Kind) bool { return kind>=Source && kind<=Other }

func (f Frame) Validate() error {
    if f.Sequence==0 || len(f.SourceID)==0 || len(f.SourceID)>maxText ||
        len(f.GenerationID)==0 || len(f.GenerationID)>maxText {
        return errors.New("C1 handoff: missing sequence or bounded generation/source identity")
    }
    digest,err:=hex.DecodeString(f.ReceiptSHA256)
    if err!=nil || len(digest)!=32 || strings.ToLower(f.ReceiptSHA256)!=f.ReceiptSHA256 {
        return errors.New("C1 handoff: invalid canonical signed receipt SHA-256")
    }
    if !isSQLKind(f.Kind) && f.Kind!=Drain && f.Kind!=Ack && f.Kind!=Start && f.Kind!=Seal && f.Kind!=Status {
        return errors.New("C1 handoff: unknown phase")
    }
    if len(f.Error)>maxError { return errors.New("C1 handoff: oversized error") }
    if f.FinalStatus>FinalAccepted ||
        (f.FinalStatus!=FinalNone && (f.Kind!=Ack || !f.Committed)){
        return errors.New("C1 handoff: forged or invalid final generation proof")
    }
    if f.Shared != (SharedRAMRef{}) {
        if !isSQLKind(f.Kind) { return errors.New("C1 handoff: control frame cannot reference RAM") }
        if err:=f.Shared.Validate();err!=nil{return err}
        if len(f.Rows)!=0 { return errors.New("C1 handoff: RAM reference cannot carry inline rows") }
    }
    if f.Kind==Start {
        if len(f.Rows)!=0||f.Committed||f.Error!=""||
            len(f.BatchIDs)==0||len(f.BatchIDs)>65535||
            len(f.BatchSQLIDs)!=0||f.ExpectedRecords<=0||
            int(f.StartBatchIndex)>=len(f.BatchIDs){
            return errors.New("C1 handoff: invalid original signed Start plan")
        }
        seen:=make(map[string]bool,len(f.BatchIDs))
        previousBatch:=""
        for _,id:=range f.BatchIDs{
            if id==""||len(id)>maxText||seen[id] {
                return errors.New("C1 handoff: duplicate or invalid original signed batch ID")
            }
            if previousBatch!="" && id<=previousBatch {
                return errors.New("C1 handoff: signed batch order was changed")
            }
            seen[id]=true
            previousBatch=id
        }
        return nil
    }
    if f.Kind!=Ack && (len(f.BatchIDs)!=0||len(f.BatchSQLIDs)!=0||
        f.ExpectedRecords!=0||f.StartBatchIndex!=0) {
        return errors.New("C1 handoff: unexpected batch-map metadata outside Start")
    }
    if f.Kind==Seal && f.SealedGroup==0{return errors.New("C1 handoff: missing signed group seal")}
    if f.Kind!=Seal && f.SealedGroup!=0{return errors.New("C1 handoff: unexpected signed group seal")}
    if f.Kind==Ack{
        if len(f.BatchIDs)!=0||f.ExpectedRecords!=0||f.StartBatchIndex!=0||
            len(f.BatchSQLIDs)>65535 {
            return errors.New("C1 handoff: invalid SQL acknowledgment map")
        }
        for _,id:=range f.BatchSQLIDs {if id<=0 {
            return errors.New("C1 handoff: invalid fi-sor assigned source-batch ID")
        }}
        if len(f.BatchSQLIDs)>0 && !f.Committed {
            return errors.New("C1 handoff: rejected SQL handoff cannot supply batch IDs")
        }
        if f.FinalStatus!=FinalNone && len(f.BatchSQLIDs)>0 {
            return errors.New("C1 handoff: START SQL identity ACK cannot claim final proof")
        }
    }
    if !isSQLKind(f.Kind) {
        if len(f.Rows)!=0 { return errors.New("C1 handoff: control frame carries data") }
        if f.Kind!=Ack && (f.Committed || f.Error!="") {
            return errors.New("C1 handoff: data/control frame forged commit acknowledgment")
        }
        if f.Kind==Ack && f.Committed==(f.Error!="") {
            return errors.New("C1 handoff: acknowledgment must be committed XOR rejected")
        }
        return nil
    }
    if (len(f.Rows)==0 && f.Shared == (SharedRAMRef{})) ||
        len(f.Rows)>MaxRows || f.Committed || f.Error!="" {
        return errors.New("C1 handoff: invalid SQL batch size or forged ACK")
    }
    var previous Row
    for i,r:=range f.Rows {
        if r.SourceBatchID<=0 || r.Ordinal<=0 || len(r.RawRecord)<2 ||
            len(r.RawRecord)>MaxSingleRecordBytes ||
            r.RawRecord[len(r.RawRecord)-1]!='\n' {
            return fmt.Errorf("C1 handoff: invalid signed row metadata at %d",i)
        }
        got:=sha256.Sum256(r.RawRecord)
        if subtle.ConstantTimeCompare(got[:],r.Digest[:])!=1 {
            return fmt.Errorf("C1 handoff: raw record SHA-256 mismatch at %d",i)
        }
        if i>0 && (r.SignedBatchIndex<previous.SignedBatchIndex ||
            (r.SignedBatchIndex==previous.SignedBatchIndex && r.Ordinal<=previous.Ordinal)) {
            return errors.New("C1 handoff: original signed row order violated")
        }
        previous=r
    }
    return nil
}

func putText(w *bytes.Buffer,text string) error {
    if len(text)>maxError {return errors.New("C1 handoff: text field too long")}
    if err:=binary.Write(w,binary.BigEndian,uint16(len(text)));err!=nil{return err}
    _,err:=w.WriteString(text)
    return err
}
func takeText(r *bytes.Reader,limit int)(string,error){
    var n uint16
    if err:=binary.Read(r,binary.BigEndian,&n);err!=nil{return "",err}
    if int(n)>limit || int(n)>r.Len() {return "",errors.New("C1 handoff: invalid field length")}
    buf:=make([]byte,int(n))
    if _,err:=io.ReadFull(r,buf);err!=nil{return "",err}
    return string(buf),nil
}

// WriteFrame sends exactly one bounded, checksummed message. The transport
// itself MUST be mutually authenticated TLS 1.3. SQL COMMIT is never inferred
// from a successful socket write.
func WriteFrame(w io.Writer,f Frame)error{
    if w==nil{return errors.New("C1 handoff: nil writer")}
    if err:=f.Validate();err!=nil{return err}
    var body bytes.Buffer
    body.WriteByte(byte(f.Kind))
    if err:=putText(&body,f.SourceID);err!=nil{return err}
    if err:=putText(&body,f.GenerationID);err!=nil{return err}
    if err:=putText(&body,f.ReceiptSHA256);err!=nil{return err}
    if err:=binary.Write(&body,binary.BigEndian,f.Sequence);err!=nil{return err}
    if f.Committed{body.WriteByte(1)}else{body.WriteByte(0)}
    if err:=putText(&body,f.Error);err!=nil{return err}
    if err:=binary.Write(&body,binary.BigEndian,uint16(len(f.Rows)));err!=nil{return err}
    for _,row:=range f.Rows{
        if err:=binary.Write(&body,binary.BigEndian,row.SignedBatchIndex);err!=nil{return err}
        if err:=binary.Write(&body,binary.BigEndian,row.SourceBatchID);err!=nil{return err}
        if err:=binary.Write(&body,binary.BigEndian,row.Ordinal);err!=nil{return err}
        if err:=binary.Write(&body,binary.BigEndian,uint32(len(row.RawRecord)));err!=nil{return err}
        if _,err:=body.Write(row.Digest[:]);err!=nil{return err}
        if _,err:=body.Write(row.RawRecord);err!=nil{return err}
        if body.Len()>MaxPayloadBytes {return errors.New("C1 handoff: SQL handoff exceeds bounded payload")}
    }
    if err:=binary.Write(&body,binary.BigEndian,uint16(len(f.BatchIDs)));err!=nil{return err}
    for _,id:=range f.BatchIDs{if err:=putText(&body,id);err!=nil{return err}}
    if err:=binary.Write(&body,binary.BigEndian,uint16(len(f.BatchSQLIDs)));err!=nil{return err}
    for _,id:=range f.BatchSQLIDs{if err:=binary.Write(&body,binary.BigEndian,id);err!=nil{return err}}
    if err:=binary.Write(&body,binary.BigEndian,f.ExpectedRecords);err!=nil{return err}
    if err:=binary.Write(&body,binary.BigEndian,f.StartBatchIndex);err!=nil{return err}
    if err:=binary.Write(&body,binary.BigEndian,f.SealedGroup);err!=nil{return err}
    if err:=putText(&body,f.Shared.Name);err!=nil{return err}
    if err:=binary.Write(&body,binary.BigEndian,f.Shared.Bytes);err!=nil{return err}
    if err:=binary.Write(&body,binary.BigEndian,f.Shared.Rows);err!=nil{return err}
    if _,err:=body.Write(f.Shared.SHA256[:]);err!=nil{return err}
    body.WriteByte(byte(f.FinalStatus))
    if body.Len()>MaxPayloadBytes{return errors.New("C1 handoff: payload exceeds ceiling")}
    sum:=sha256.Sum256(body.Bytes())
    var hdr [44]byte
    copy(hdr[:8],magic[:])
    binary.BigEndian.PutUint32(hdr[8:12],uint32(body.Len()))
    copy(hdr[12:44],sum[:])
    for left:=hdr[:];len(left)>0;{
        n,err:=w.Write(left)
        if err!=nil{return err}
        if n<=0{return io.ErrShortWrite}
        left=left[n:]
    }
    // Write is not required to consume every byte. Never acknowledge a
    // short socket write as a complete durable handoff.
    data:=body.Bytes()
    for len(data)>0{
        n,err:=w.Write(data)
        if err!=nil{return err}
        if n<=0{return io.ErrShortWrite}
        data=data[n:]
    }
    return nil
}
func ReadFrame(r io.Reader)(Frame,error){
    var empty Frame
    if r==nil{return empty,errors.New("C1 handoff: nil reader")}
    var hdr [44]byte
    if _,err:=io.ReadFull(r,hdr[:]);err!=nil{return empty,err}
    if !bytes.Equal(hdr[:8],magic[:]) {return empty,errors.New("C1 handoff: protocol magic mismatch")}
    size:=binary.BigEndian.Uint32(hdr[8:12])
    if size==0||size>MaxPayloadBytes{return empty,errors.New("C1 handoff: frame exceeds memory ceiling")}
    payload:=make([]byte,int(size))
    if _,err:=io.ReadFull(r,payload);err!=nil{return empty,err}
    sum:=sha256.Sum256(payload)
    if subtle.ConstantTimeCompare(sum[:],hdr[12:44])!=1{
        return empty,errors.New("C1 handoff: frame digest mismatch")
    }
    rd:=bytes.NewReader(payload)
    kind,err:=rd.ReadByte();if err!=nil{return empty,err}
    f:=Frame{Kind:Kind(kind)}
    if f.SourceID,err=takeText(rd,maxText);err!=nil{return empty,err}
    if f.GenerationID,err=takeText(rd,maxText);err!=nil{return empty,err}
    if f.ReceiptSHA256,err=takeText(rd,64);err!=nil{return empty,err}
    if err=binary.Read(rd,binary.BigEndian,&f.Sequence);err!=nil{return empty,err}
    committed,err:=rd.ReadByte();if err!=nil{return empty,err}
    if committed>1{return empty,errors.New("C1 handoff: invalid commit flag")}
    f.Committed=committed==1
    if f.Error,err=takeText(rd,maxError);err!=nil{return empty,err}
    var count uint16
    if err=binary.Read(rd,binary.BigEndian,&count);err!=nil{return empty,err}
    if count>MaxRows{return empty,errors.New("C1 handoff: too many rows")}
    f.Rows=make([]Row,0,int(count))
    for i:=0;i<int(count);i++{
        var row Row
        var n uint32
        for _,v:=range []any{&row.SignedBatchIndex,&row.SourceBatchID,&row.Ordinal,&n}{
            if err=binary.Read(rd,binary.BigEndian,v);err!=nil{return empty,err}
        }
        if n>MaxSingleRecordBytes || uint64(n)+32>uint64(rd.Len()){
            return empty,errors.New("C1 handoff: unbounded or truncated record")
        }
        if _,err=io.ReadFull(rd,row.Digest[:]);err!=nil{return empty,err}
        row.RawRecord=make([]byte,int(n))
        if _,err=io.ReadFull(rd,row.RawRecord);err!=nil{return empty,err}
        f.Rows=append(f.Rows,row)
    }
    var batches uint16
    if err=binary.Read(rd,binary.BigEndian,&batches);err!=nil{return empty,err}
    f.BatchIDs=make([]string,0,int(batches))
    for i:=0;i<int(batches);i++{
        id,e:=takeText(rd,maxText);if e!=nil{return empty,e}
        f.BatchIDs=append(f.BatchIDs,id)
    }
    var sqlBatches uint16
    if err=binary.Read(rd,binary.BigEndian,&sqlBatches);err!=nil{return empty,err}
    if int(sqlBatches)*8>rd.Len(){return empty,errors.New("C1 handoff: truncated SQL batch map")}
    f.BatchSQLIDs=make([]int64,0,int(sqlBatches))
    for i:=0;i<int(sqlBatches);i++{
        var id int64
        if err=binary.Read(rd,binary.BigEndian,&id);err!=nil{return empty,err}
        f.BatchSQLIDs=append(f.BatchSQLIDs,id)
    }
    if err=binary.Read(rd,binary.BigEndian,&f.ExpectedRecords);err!=nil{return empty,err}
    if err=binary.Read(rd,binary.BigEndian,&f.StartBatchIndex);err!=nil{return empty,err}
    if err=binary.Read(rd,binary.BigEndian,&f.SealedGroup);err!=nil{return empty,err}
    if f.Shared.Name,err=takeText(rd,64);err!=nil{return empty,err}
    if err=binary.Read(rd,binary.BigEndian,&f.Shared.Bytes);err!=nil{return empty,err}
    if err=binary.Read(rd,binary.BigEndian,&f.Shared.Rows);err!=nil{return empty,err}
    if _,err=io.ReadFull(rd,f.Shared.SHA256[:]);err!=nil{return empty,err}
    proof,err:=rd.ReadByte()
    if err!=nil{return empty,err}
    f.FinalStatus=FinalStatus(proof)
    if rd.Len()!=0{return empty,errors.New("C1 handoff: trailing unrecognized bytes")}
    if err=f.Validate();err!=nil{return empty,err}
    return f,nil
}
