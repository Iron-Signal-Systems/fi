// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package spool

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAbandonUnpublishedLeavesEvidenceButNeverPublishesPartialBatch(t *testing.T) {
	dir:=t.TempDir()
	writer,err:=NewWriter(dir, 4096, CollectorIdentity{
		ExecutablePath:"FI-collector-test",
		ExecutableSHA256:strings.Repeat("a",64),
	})
	if err!=nil {t.Fatal(err)}
	if err:=writer.Append("VolumeUSNMinimalChangeV2","volume:data",map[string]any{"usn":"100"});err!=nil {t.Fatal(err)}
	work:=writer.openPath
	if work=="" {t.Fatal("source window was not opened")}
	if err:=writer.AbandonUnpublished();err!=nil {t.Fatal(err)}
	if _,err:=os.Stat(work);err!=nil {t.Fatalf("incomplete source evidence was erased: %v",err)}
	if err:=writer.Append("VolumeUSNReadBoundaryV2","volume:data",map[string]any{"next_usn":"200"});!errors.Is(err,ErrWriterClosed) {
		t.Fatalf("abandoned writer accepted terminal boundary: %v",err)
	}
	if err:=writer.Close();err!=nil {t.Fatal(err)}
	if err:=writer.AbandonUnpublished();err!=nil {t.Fatal(err)}
	if len(writer.FinalizedBatches())!=0 {t.Fatalf("abandoned work was published: %+v",writer.FinalizedBatches())}
	children,err:=os.ReadDir(dir)
	if err!=nil {t.Fatal(err)}
	for _,child:=range children {
		if strings.HasSuffix(child.Name(),".manifest.json") || strings.HasSuffix(child.Name(),".jsonl") {
			t.Fatalf("partial source batch became visible: %s",filepath.Join(dir,child.Name()))
		}
	}
}

func TestAbandonUnpublishedDoesNotDeleteAlreadyPublishedBatch(t *testing.T) {
	dir:=t.TempDir()
	writer,err:=NewWriter(dir, 2, CollectorIdentity{
		ExecutablePath:"FI-collector-test",
		ExecutableSHA256:strings.Repeat("b",64),
	})
	if err!=nil {t.Fatal(err)}
	for i:=0;i<2;i++ {
		if err:=writer.Append("FileObservation","scope-a",map[string]any{"index":i});err!=nil {t.Fatal(err)}
	}
	finalized:=writer.FinalizedBatches()
	if len(finalized)!=1 {t.Fatalf("expected pre-existing published evidence: %d",len(finalized))}
	if err:=writer.AbandonUnpublished();err!=nil {t.Fatal(err)}
	if err:=writer.Close();err!=nil {t.Fatal(err)}
	if _,err:=VerifyManifest(finalized[0].ManifestPath);err!=nil {
		t.Fatalf("abandon removed previously published source evidence: %v",err)
	}
}
