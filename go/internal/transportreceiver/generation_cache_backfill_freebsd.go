//go:build freebsd

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Explicit one-generation receiver verified-cache backfill. Used only for
// signed, already-recorded generations created before cached batch publication.
// No receiver restart sweep, listener, READY state change, sender ACK or SoR SQL.
package transportreceiver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/generationrecorder"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportgeneration"
)

// BackfillRecordedGenerationCache fully revalidates one immutable original
// signed FIGT and its recorded receipt. Cache publication is permitted only
// AFTER all source trust, framing, signing and batch semantics match. It never
// writes a new recorded receipt: only exact already-recorded is accepted.
func BackfillRecordedGenerationCache(ctx context.Context,c Config,sourceID,generationID string)(
	generationrecorder.DurableResult,error,
){
	var empty generationrecorder.DurableResult
	if ctx==nil||ctx.Err()!=nil||!c.GenerationEnabled||
		c.GenerationVerifiedCacheRoot==""||
		c.GenerationCustodyRoot==""||c.GenerationRecordedRoot==""||
		c.LookupSource==nil||sourceID==""||generationID==""{
		return empty,errors.New("FI receiver cache backfill: exact original signed generation and enabled receiver cache required")
	}
	if err:=validateGenerationListenerConfig(c);err!=nil{return empty,err}
	source,found:=c.LookupSource(sourceID)
	if !found||!source.Enabled||source.SourceID!=sourceID{
		return empty,errors.New("FI receiver cache backfill: source not actively enrolled with exact identity")
	}
	name:=generationrecorder.RecordedReceiptObjectName(sourceID,generationID)
	receiptDir:=c.GenerationRecordedRoot
	if c.GenerationSourceNamespaces{
		dir,err:=generationrecorder.RecordedSourceDirectory(receiptDir,sourceID)
		if err!=nil{return empty,err}
		receiptDir=dir
	}
	receiptPath:=filepath.Join(receiptDir,name)
	info,err:=os.Lstat(receiptPath)
	if err!=nil{return empty,fmt.Errorf("FI receiver cache backfill: missing immutable recorded receipt: %w",err)}
	if !info.Mode().IsRegular()||info.Mode().Perm()!=0400||info.Size()<=0||info.Size()>256<<10{
		return empty,errors.New("FI receiver cache backfill: unsafe original recorded receipt")
	}
	raw,err:=os.ReadFile(receiptPath)
	if err!=nil{return empty,err}
	receipt,err:=generationrecorder.UnmarshalRecordedReceipt(raw)
	if err!=nil{return empty,err}
	if receipt.Descriptor.SourceID!=sourceID||receipt.Descriptor.GenerationID!=generationID{
		return empty,errors.New("FI receiver cache backfill: original recorded receipt identity conflict")
	}
	sum:=sha256.Sum256(raw)
	wantSHA:=hex.EncodeToString(sum[:])
	custodyPath:=filepath.Join(c.GenerationCustodyRoot,
		transportgeneration.DurableCustodyObjectName(sourceID,generationID))
	custodyInfo,err:=os.Lstat(custodyPath)
	if err!=nil{return empty,err}
	if !custodyInfo.Mode().IsRegular()||custodyInfo.Mode().Perm()!=0400||custodyInfo.Size()<=0{
		return empty,errors.New("FI receiver cache backfill: original signed FIGT custody is unsafe")
	}
	config:=generationReceiveConfigFromListener(c,time.Now())
	config.Custody.Receive.Source=source
	// The discovered-custody recorder verifies the exact signed FIGT, source
	// certificate+CRL, complete transfer/manifest semantics and existing
	// immutable receipt before allowing receiver cache publication.
	result,err:=generationrecorder.RecordDiscoveredCustodyDurably(
		transportgeneration.DiscoveredCustody{
			Path:custodyPath,Bytes:uint64(custodyInfo.Size()),
		},config.Custody,config.Recorder)
	if err!=nil{return empty,err}
	if result.Disposition!=generationrecorder.RecordedDispositionAlreadyRecorded||
		result.ReceiptSHA256!=wantSHA||result.Receipt.TransferSHA256!=receipt.TransferSHA256||
		result.Receipt.BatchCount!=receipt.BatchCount||
		result.Receipt.RecordCount!=receipt.RecordCount{
		return empty,errors.New("FI receiver cache backfill: exact original recorded receipt not preserved")
	}
	return result,nil
}
