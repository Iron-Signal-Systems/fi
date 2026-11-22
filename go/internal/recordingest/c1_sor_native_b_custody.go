//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Independent verifier B streams ORIGINAL signed receiver custody through
// its own trust validation and read-only PostgreSQL SourceParent/typed
// verification. It does not materialize 65+ GiB of custody as a second
// durable file tree, touch fi-ingest RAM handoffs or write any SQL. The
// original signed source is the recoverable authority.
package recordingest

import (
    "bufio"
    "bytes"
    "context"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "io"
    "os"
    "path/filepath"
    "time"

    "github.com/Iron-Signal-Systems/fi/go/internal/generationrecorder"
    "github.com/Iron-Signal-Systems/fi/go/internal/spool"
    "github.com/Iron-Signal-Systems/fi/go/internal/transportgeneration"
    "github.com/jackc/pgx/v5"
)

const c1NativeBMaxAuditRows=2048
// C1NativeBCustodyConfig is used only by the explicitly authorized
// development fi-sor offline publication command. It carries paths and
// byte ceilings, never raw original custody or a PostgreSQL DSN.
type C1NativeBCustodyConfig = c1NativeBCustodyConfig

type c1NativeBCustodyConfig struct {
    CustodyRoot string
    RecordedRoot string
    SourceNamespaces bool
    MaxCanonicalBytes uint64
    MaxEncodedBytes uint64
    MaxManifestBytes uint64
}

// Every signed record is verified as an original LF-terminated JSONL
// envelope and matched against its committed source-record digest and
// typed projection root in the private fi-sor database.
func c1NativeBVerifyData(ctx context.Context,conn *pgx.Conn,raw io.Reader,
    batchIndex int,batchID int64,expected PreparedBatch,
    targetSchema ...string)error{
    if ctx==nil||conn==nil||raw==nil||batchIndex<0||batchID<=0||
        expected.BatchID==""||expected.Manifest.RecordCount<=0||
        expected.Manifest.DataBytes<=0{
        return errors.New("C1 B custody: invalid signed batch audit inputs")
    }
    digest:=sha256.New()
    reader:=bufio.NewReaderSize(io.TeeReader(raw,digest),128<<10)
    var sourceBytes,sourceRecords int64
    chunk:=make([]privateP6Record,0,c1NativeBMaxAuditRows)
    audit:=func()error{
        if len(chunk)==0{return nil}
        tx,e:=conn.BeginTx(ctx,pgx.TxOptions{IsoLevel:pgx.RepeatableRead,AccessMode:pgx.ReadOnly})
        if e!=nil{return e}
        defer tx.Rollback(context.Background())
        states,e:=c1AuditCommittedRowStates(ctx,tx,chunk,targetSchema...)
        if e!=nil{return e}
        for i,state:=range states{
            if !state.ParentCommitted||!state.TypedRootCommitted{
                return fmt.Errorf("C1 B custody: original signed batch %s ordinal %d not fully committed",
                    expected.BatchID,chunk[i].ordinal)
            }
        }
        if e=tx.Commit(ctx);e!=nil{return e}
        chunk=chunk[:0]
        return nil
    }
    for{
        if err:=ctx.Err();err!=nil{return err}
        // The original recorder limits each batch to 64 MiB; enforce
        // its bound while reading even if custody has been tampered with.
        line,err:=reader.ReadBytes('\n')
        if len(line)==0&&errors.Is(err,io.EOF){break}
        if err!=nil{
            return fmt.Errorf("C1 B custody: incomplete signed LF record batch %s: %w",expected.BatchID,err)
        }
        sourceBytes+=int64(len(line))
        sourceRecords++
        if len(line)<2||len(line)>64<<20||
            sourceBytes>expected.Manifest.DataBytes||
            sourceRecords>int64(expected.Manifest.RecordCount){
            return errors.New("C1 B custody: original source record violates signed byte/ordinal bounds")
        }
        prepared,e:=PrepareSourceRecord(line)
        if e!=nil{return fmt.Errorf("C1 B custody: signed source envelope %s/%d: %w",
            expected.BatchID,sourceRecords,e)}
        chunk=append(chunk,privateP6Record{
            signedBatchIndex:batchIndex,sourceBatchID:batchID,
            ordinal:sourceRecords,prepared:prepared,
        })
        if len(chunk)==c1NativeBMaxAuditRows{
            if e=audit();e!=nil{return e}
        }
    }
    if err:=audit();err!=nil{return err}
    got:=hex.EncodeToString(digest.Sum(nil))
    if sourceBytes!=expected.Manifest.DataBytes||
        sourceRecords!=int64(expected.Manifest.RecordCount)||
        got!=expected.Manifest.DataSHA256{
        return fmt.Errorf("C1 B custody: signed data source changed batch %s rows=%d/%d bytes=%d/%d SHA=%s/%s",
            expected.BatchID,sourceRecords,expected.Manifest.RecordCount,
            sourceBytes,expected.Manifest.DataBytes,got,expected.Manifest.DataSHA256)
    }
    return nil
}

// c1NativeBVerifySignedCustody independently verifies the original
// receiver trust roots, signed transfer envelope, manifest bytes, receipt
// metadata, every original JSONL row and every corresponding private
// SourceParent/typed root. It runs ONLY after all commit-ready groups passed.
// It is fail-closed, read-only for SQL, and never copies custody to disk.
func c1NativeBVerifySignedCustody(ctx context.Context,conn *pgx.Conn,
    p c1NativeBPlan,cfg c1NativeBCustodyConfig)error{
    if ctx==nil||conn==nil||cfg.CustodyRoot==""||cfg.RecordedRoot==""||
        !filepath.IsAbs(cfg.CustodyRoot)||!filepath.IsAbs(cfg.RecordedRoot)||
        cfg.MaxCanonicalBytes==0||cfg.MaxEncodedBytes==0||
        cfg.MaxManifestBytes==0||cfg.MaxManifestBytes>1<<20{
        return errors.New("C1 B custody: explicit read-only signed custody roots and limits required")
    }
    if err:=c1ValidateNativeBPlan(p);err!=nil{return err}
    name:=generationrecorder.RecordedReceiptObjectName(p.Start.SourceID,p.Start.GenerationID)
    receiptRoot:=cfg.RecordedRoot
    if cfg.SourceNamespaces{
        sourceDir,err:=generationrecorder.RecordedSourceDirectory(cfg.RecordedRoot,p.Start.SourceID)
        if err!=nil{return err}
        receiptRoot=sourceDir
    }
    receiptRaw,err:=readImmutableReceipt(filepath.Join(receiptRoot,name))
    if err!=nil{return fmt.Errorf("C1 B custody: independently read recorded receipt: %w",err)}
    receiptHash:=sha256.Sum256(receiptRaw)
    receipt,err:=generationrecorder.UnmarshalRecordedReceipt(receiptRaw)
    if err!=nil{return err}
    if hex.EncodeToString(receiptHash[:])!=p.Start.ReceiptSHA256||
        receipt.Descriptor.SourceID!=p.Start.SourceID||
        receipt.Descriptor.GenerationID!=p.Start.GenerationID||
        receipt.TransferSHA256!=p.Transfer||
        receipt.BatchCount!=uint64(len(p.Batches)){
        return errors.New("C1 B custody: immutable recorded receipt mismatches signed SQL generation")
    }
    var originalRows int64
    var originalBytes uint64
    for _,batch:=range p.Batches{
        originalRows+=int64(batch.Manifest.RecordCount)
        originalBytes+=uint64(batch.Manifest.DataBytes)
    }
    if receipt.RecordCount!=uint64(originalRows)||receipt.DataBytes!=originalBytes{
        return errors.New("C1 B custody: original recorder receipt totals mismatch verified manifest plan")
    }

    trust,err:=loadInstalledGenerationTrust(p.Start.SourceID)
    if err!=nil{return fmt.Errorf("C1 B custody: installed receiver trust validation: %w",err)}
    originalPath:=filepath.Join(cfg.CustodyRoot,
        transportgeneration.DurableCustodyObjectName(p.Start.SourceID,p.Start.GenerationID))
    info,err:=os.Lstat(originalPath)
    if err!=nil{return err}
    if !info.Mode().IsRegular()||info.Mode().Perm()!=0400||info.Size()<=0{
        return errors.New("C1 B custody: original signed generation is not an immutable regular file")
    }

    i:=0
    expectedArtifacts:=len(p.Batches)*2
    factory:=func(descriptor transportgeneration.Descriptor)(
        transportgeneration.CanonicalArtifactHandler,error,
    ){
        if descriptor!=receipt.Descriptor{
            return nil,errors.New("C1 B custody: signed transfer descriptor differs from immutable recorder receipt")
        }
        return func(name string,r io.Reader)error{
            if i>=expectedArtifacts{return errors.New("C1 B custody: extra signed canonical artifact")}
            idx:=i/2
            batch:=p.Batches[idx]
            // Recorder's canonical bundle always uses data then manifest
            // for each signed batch. Any path traversal/order change fails.
            dataName:="batch-"+batch.BatchID+".jsonl"
            manifestName:="batch-"+batch.BatchID+".manifest.json"
            if i%2==0{
                if name!=dataName{
                    return fmt.Errorf("C1 B custody: wrong signed batch file %q expected %q",name,dataName)
                }
                if err:=c1NativeBVerifyData(ctx,conn,r,idx,p.SQLIDs[idx],batch,p.SQLSchema);err!=nil{
                    return fmt.Errorf("C1 B custody: independent SourceParent/typed readback batch %d: %w",idx,err)
                }
            }else{
                if name!=manifestName{
                    return fmt.Errorf("C1 B custody: wrong signed manifest file %q expected %q",name,manifestName)
                }
                raw,e:=io.ReadAll(io.LimitReader(r,int64(cfg.MaxManifestBytes)+1))
                if e!=nil{return e}
                if len(raw)==0||uint64(len(raw))>cfg.MaxManifestBytes{
                    return errors.New("C1 B custody: signed manifest exceeds verified bound")
                }
                h:=sha256.Sum256(raw)
                if hex.EncodeToString(h[:])!=batch.ManifestSHA256{
                    return errors.New("C1 B custody: original signed manifest digest differs from SQL ledger")
                }
                manifest,e:=spool.DecodeManifest(bytes.NewReader(raw))
                if e!=nil{return e}
                if manifest.BatchID!=batch.BatchID||
                    manifest.DataFile!=dataName||
                    manifest.RecordCount!=batch.Manifest.RecordCount||
                    manifest.DataBytes!=batch.Manifest.DataBytes||
                    manifest.DataSHA256!=batch.Manifest.DataSHA256{
                    return errors.New("C1 B custody: signed manifest metadata differs from private PostgreSQL source_batch")
                }
            }
            i++
            return nil
        },nil
    }
    original,e:=transportgeneration.ReadDiscoveredDurableCustodyArtifacts(
        transportgeneration.DiscoveredCustody{Bytes:uint64(info.Size()),Path:originalPath},
        transportgeneration.CustodyConfig{
            RootDir:cfg.CustodyRoot,
            Receive:transportgeneration.ReceiveConfig{
                BatchCRL:trust.BatchCRL,BatchIssuer:trust.BatchIssuer,
                CurrentTime:time.Now(),MaxCanonicalBytes:cfg.MaxCanonicalBytes,
                MaxEncodedBytes:cfg.MaxEncodedBytes,Root:trust.Root,
                Source:trust.Source,
            },
        },factory)
    if e!=nil{return fmt.Errorf("C1 B custody: original receiver cryptographic verification failed: %w",e)}
    if original.Transfer.Descriptor!=receipt.Descriptor||
        original.Transfer.MetadataBytes!=receipt.MetadataBytes||
        original.Transfer.MetadataSHA256!=receipt.MetadataSHA256||
        original.Transfer.TransferBytes!=receipt.TransferBytes||
        original.Transfer.TransferSHA256!=receipt.TransferSHA256||
        i!=expectedArtifacts{
        return errors.New("C1 B custody: original signed transfer/receipt/artifact completeness mismatch")
    }
    fmt.Printf("FI C1 B ORIGINAL SIGNED CUSTODY PASS source=%s generation=%s batches=%d records=%d data_bytes=%d SQL_readonly=true staged_copy=false canonical_publication=false\n",
        p.Start.SourceID,p.Start.GenerationID,len(p.Batches),originalRows,originalBytes)
    return nil
}

