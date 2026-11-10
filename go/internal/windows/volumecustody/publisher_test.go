// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package volumecustody

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
)

func oneWindowPublisher(dir string) OneBatchSpoolPublisher {
	return OneBatchSpoolPublisher{
		Directory:dir,
		Collector:spool.CollectorIdentity{
			ExecutablePath:`C:\Program Files\FI\fi.exe`,
			ExecutableSHA256:strings.Repeat("a",64),
		},
	}
}

func TestOneBatchPublisherRetainsCompleteUSNWindowAndVerifiesManifest(t *testing.T) {
	saved,journal,window:=custodyFixture()
	dir:=t.TempDir()
	manifest,err:=oneWindowPublisher(dir).PublishWindow(context.Background(),window)
	if err!=nil||manifest=="" {t.Fatalf("cannot publish one whole source window: %q %v",manifest,err)}
	verification,err:=spool.VerifyManifest(manifest)
	if err!=nil||!verification.Verified||verification.Manifest.RecordCount!=len(window.Changes)+1 {
		t.Fatalf("published FI spool pair invalid: %+v %v",verification,err)
	}
	proposed,err:=ProposeAfterPublishedWindow(saved,journal,window,dir,manifest)
	if err!=nil||proposed.NextUSN!="2500" {
		t.Fatalf("native-source boundary lost after publication: %+v %v",proposed,err)
	}
}

func TestOneBatchPublisherPreservesZeroChangeReadBoundary(t *testing.T) {
	saved,journal,window:=custodyFixture()
	window.Changes=nil
	window.Boundary.SourceRecordCount=0
	dir:=t.TempDir()
	manifest,err:=oneWindowPublisher(dir).PublishWindow(context.Background(),window)
	if err!=nil {t.Fatal(err)}
	proposed,err:=ProposeAfterPublishedWindow(saved,journal,window,dir,manifest)
	if err!=nil||proposed.NextUSN!="2500" {
		t.Fatalf("zero-record source pass lacked durable terminal boundary: %+v %v",proposed,err)
	}
	check,err:=spool.VerifyManifest(manifest)
	if err!=nil||check.Manifest.RecordCount!=1 {t.Fatalf("empty window must publish one boundary only: %+v %v",check,err)}
}

func TestOneBatchPublisherRefusesMalformedWindowsBeforeAnyFilesystemChange(t *testing.T) {
	for _,tc:=range []struct{
		name string
		mutate func(*Window)
	}{
		{"mismatched count",func(w *Window){w.Boundary.SourceRecordCount=2}},
		{"zero cursor",func(w *Window){w.Boundary.NextUSN=w.Boundary.StartUSN}},
		{"missing enrollment",func(w *Window){w.Boundary.EnrollmentID=""}},
		{"invalid epoch",func(w *Window){w.Boundary.Epoch=0}},
		{"unknown raw reference width",func(w *Window){w.Changes[0].NTFSRecordVersion=4}},
		{"unbounded window",func(w *Window){w.Changes=make([]MinimalChange,maxWindowChanges+1)}},
	} {
		t.Run(tc.name,func(t *testing.T){
			_,_,w:=custodyFixture()
			tc.mutate(&w)
			dir:=t.TempDir()
			manifest,err:=oneWindowPublisher(dir).PublishWindow(context.Background(),w)
			if !errors.Is(err,ErrUnsafeWindow)||manifest!="" {
				t.Fatalf("unsafe source window published: %q %v",manifest,err)
			}
			children,err:=os.ReadDir(dir)
			if err!=nil||len(children)!=0 {
				t.Fatalf("invalid source created spool artifacts before validation: %v %v",children,err)
			}
		})
	}
}

func TestOneBatchPublisherCancellationAndInvalidCollectorFailClosed(t *testing.T) {
	_,_,w:=custodyFixture()
	ctx,cancel:=context.WithCancel(context.Background())
	cancel()
	dir:=t.TempDir()
	if manifest,err:=oneWindowPublisher(dir).PublishWindow(ctx,w);!errors.Is(err,context.Canceled)||manifest!="" {
		t.Fatalf("cancelled source pass opened FI spool: %q %v",manifest,err)
	}
	children,err:=os.ReadDir(dir)
	if err!=nil||len(children)!=0 {t.Fatalf("cancelled pass created source artifacts: %v %v",children,err)}
	p:=oneWindowPublisher(dir)
	p.Collector.ExecutableSHA256="not-a-hash"
	if manifest,err:=p.PublishWindow(context.Background(),w);err==nil||manifest!="" {
		t.Fatalf("invalid executable identity accepted: %q %v",manifest,err)
	}
}

func TestOneWindowCoordinatorAcceptsOnlyVerifiedConcreteSpoolPublisher(t *testing.T) {
	h:=newPassHarness(t)
	d:=h.dep()
	d.Publisher=oneWindowPublisher(h.spoolDir)
	result,err:=ProcessOneWindow(context.Background(),"data",d)
	if err!=nil||!result.PublicationAttempted||!result.Published||
		!result.CommitAttempted||!result.CheckpointCommitted||
		result.ManifestPath==""||h.checked.NextUSN!="2500" {
		t.Fatalf("one-window actual source spool publication failed: %+v %v",result,err)
	}
	check,err:=spool.VerifyManifest(result.ManifestPath)
	if err!=nil||check.Manifest.RecordCount!=2 {
		t.Fatalf("coordinator did not publish complete source boundary: %+v %v",check,err)
	}
}
