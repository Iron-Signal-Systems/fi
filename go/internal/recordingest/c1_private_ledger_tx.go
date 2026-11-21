// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Thin PRIVATE SQL projection helper, not an ingest or schema activation
// path. It uses the original Source of Record generation and source_batch
// SQL writer and an externally owned transaction. CI's established
// PostgreSQL18 fixture calls this without enabling any C1 runtime service.
package recordingest

import (
    "context"
    "encoding/hex"
    "errors"
    "fmt"

    "github.com/jackc/pgx/v5"
)

// c1StageOriginalPrivateLedgerTx inserts ONLY exact signed generation and
// original signed source-batch metadata. No SourceParent, typed projection,
// Accepted journal or canonical SQL table is written.
func c1StageOriginalPrivateLedgerTx(ctx context.Context,tx pgx.Tx,
    original *PreparedGeneration)([]int64,error){
    if ctx==nil||tx==nil||original==nil||len(original.Batches)==0||
        len(original.ReceiptSHA256)!=64{
        return nil,errors.New("C1 bootstrap: original signed receipt and owning SQL transaction required")
    }
    digest,err:=hex.DecodeString(original.ReceiptSHA256)
    if err!=nil||len(digest)!=32{
        return nil,errors.New("C1 bootstrap: invalid original signed receipt digest")
    }
    shadow:=privateProjectionTx{Tx:tx}
    id,err:=insertRecordedGeneration(ctx,shadow,original)
    if err!=nil{return nil,fmt.Errorf("C1 bootstrap: private signed generation insert: %w",err)}
    profile:=&sourceBatchBulkProfile{}
    ids,err:=copySourceBatches(ctx,shadow,id,original.Batches,profile)
    if err!=nil{return nil,fmt.Errorf("C1 bootstrap: original source-batch ledger: %w",err)}
    if len(ids)!=len(original.Batches){
        return nil,errors.New("C1 bootstrap: SQL generated source-batch mapping incomplete")
    }
    for _,id:=range ids{
        if id<=0{return nil,errors.New("C1 bootstrap: missing PostgreSQL-generated original SQL batch identity")}
    }
    return ids,nil
}
