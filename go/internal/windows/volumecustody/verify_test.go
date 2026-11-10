// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package volumecustody

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/volumeepoch"
)

const (
	testGUID = `\\?\Volume{18fed846-4275-4251-b698-f268192100f2}\`
	testOtherGUID = `\\?\Volume{f21d9dd4-8111-4be8-83e9-a1429a261cdf}\`
)

func custodyFixture() (volumeepoch.Checkpoint, volumeepoch.Journal, Window) {
	id := volumeepoch.Identity{
		VolumeGUID: testGUID, VolumeSerial: "15172277115761558407", JournalID: "134367117582369963",
	}
	cp := volumeepoch.Checkpoint{
		Version: volumeepoch.CheckpointVersion,
		EnrollmentID: "data", Epoch: 3, Identity: id, NextUSN: "2000",
	}
	journal := volumeepoch.Journal{
		Identity: id, FirstUSN: "1000", LowestValidUSN: "1000", NextUSN: "3000",
	}
	change := MinimalChange{
		Version: MinimalFactVersion, USN: "2200", NTFSRecordVersion: 2,
		FileReferenceHex: "0000000000000001",
		ParentReferenceHex: "0000000000000002",
		ReasonFlags: 0x80000100,
	}
	window := Window{
		Boundary: ReadBoundary{
			Version: BoundaryVersion, EnrollmentID: "data", Epoch: 3, Identity: id,
			StartUSN: "2000", NextUSN: "2500", SourceRecordCount: 1,
		},
		Changes: []MinimalChange{change},
	}
	return cp, journal, window
}

func publishFixture(t *testing.T, dir string, source Window, changeKind string, boundaryKind string, scope string) string {
	t.Helper()
	writer, err := spool.NewWriter(dir, spool.DefaultBatchSize, spool.CollectorIdentity{
		ExecutablePath: `C:\Program Files\FI\fi.exe`,
		ExecutableSHA256: strings.Repeat("a", 64),
	})
	if err != nil { t.Fatal(err) }
	for _, fact := range source.Changes {
		if err := writer.Append(changeKind, scope, fact); err != nil { t.Fatal(err) }
	}
	if err := writer.Append(boundaryKind, scope, source.Boundary); err != nil { t.Fatal(err) }
	if err := writer.Close(); err != nil { t.Fatal(err) }
	batches := writer.FinalizedBatches()
	if len(batches) != 1 {
		t.Fatalf("one bounded source window produced %d spool batches", len(batches))
	}
	return batches[0].ManifestPath
}

func TestPublishedVolumeWindowReturnsOnlyInMemoryCandidate(t *testing.T) {
	cp, journal, window := custodyFixture()
	dir := t.TempDir()
	manifest := publishFixture(t, dir, window, MinimalFactRecordKind, BoundaryRecordKind, "volume:data")
	next, err := ProposeAfterPublishedWindow(cp, journal, window, dir, manifest)
	if err != nil { t.Fatal(err) }
	if next.NextUSN != "2500" || next.EnrollmentID != cp.EnrollmentID ||
		next.Epoch != cp.Epoch || next.Identity != cp.Identity {
		t.Fatalf("incorrect in-memory cursor proposal: %+v", next)
	}
	if cp.NextUSN != "2000" {
		t.Fatal("input checkpoint was mutated")
	}
}

func TestWindowsPublishedSpoolCanonicalPathCaseAlias(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows physical directory canonicalization is platform-specific")
	}
	cp, journal, window := custodyFixture()
	dir := t.TempDir()
	manifest := publishFixture(t, dir, window, MinimalFactRecordKind, BoundaryRecordKind, "volume:data")
	// The writer records the GetFinalPathNameByHandleW-resolved physical path.
	// A case-distinct configured path is the same Windows directory and must
	// not be mistaken for a foreign publication.
	next, err := ProposeAfterPublishedWindow(cp, journal, window, strings.ToUpper(dir), manifest)
	if err != nil || next.NextUSN != "2500" {
		t.Fatalf("native spool alias rejected: %+v %v", next, err)
	}
}

func TestEvenZeroChangeWindowsRequirePublishedTerminalBoundary(t *testing.T) {
	cp, journal, window := custodyFixture()
	window.Changes = nil
	window.Boundary.SourceRecordCount = 0
	dir := t.TempDir()
	manifest := publishFixture(t, dir, window, MinimalFactRecordKind, BoundaryRecordKind, "volume:data")
	next, err := ProposeAfterPublishedWindow(cp, journal, window, dir, manifest)
	if err != nil || next.NextUSN != "2500" {
		t.Fatalf("empty bounded source evidence not verified: %+v %v", next, err)
	}
}

func TestPublishedVolumeWindowRejectsUntrustedOrWrongSpoolEvidence(t *testing.T) {
	cp, journal, window := custodyFixture()
	for _, tc := range []struct{
		name string
		changeKind string
		boundaryKind string
		scope string
		change func(*Window)
	}{
		{"wrong change kind", "FileObservation", BoundaryRecordKind, "volume:data", nil},
		{"wrong boundary kind", MinimalFactRecordKind, "USNReadBoundary", "volume:data", nil},
		{"legacy scope", MinimalFactRecordKind, BoundaryRecordKind, "root:data", nil},
		{"wrong spooled USN", MinimalFactRecordKind, BoundaryRecordKind, "volume:data", func(w *Window){w.Changes[0].USN = "2300"}},
		{"wrong spooled count", MinimalFactRecordKind, BoundaryRecordKind, "volume:data", func(w *Window){w.Boundary.SourceRecordCount = 0}},
		{"wrong spooled boundary", MinimalFactRecordKind, BoundaryRecordKind, "volume:data", func(w *Window){w.Boundary.NextUSN = "2600"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			published := window
			published.Changes = append([]MinimalChange(nil), window.Changes...)
			if tc.change != nil { tc.change(&published) }
			manifest := publishFixture(t, dir, published, tc.changeKind, tc.boundaryKind, tc.scope)
			if _, err := ProposeAfterPublishedWindow(cp, journal, window, dir, manifest); !errors.Is(err, ErrUnverifiedCustody) {
				t.Fatalf("untrusted or altered publication accepted: %v", err)
			}
		})
	}
}

func TestPublishedVolumeWindowRejectsCorruptAndMislocatedArtifacts(t *testing.T) {
	cp, journal, window := custodyFixture()
	dir := t.TempDir()
	manifest := publishFixture(t, dir, window, MinimalFactRecordKind, BoundaryRecordKind, "volume:data")
	if _, err := ProposeAfterPublishedWindow(cp, journal, window, filepath.Dir(dir), manifest); !errors.Is(err, ErrUnverifiedCustody) {
		t.Fatalf("foreign spool parent accepted: %v", err)
	}
	if _, err := ProposeAfterPublishedWindow(cp, journal, window, dir, filepath.Join(dir, "missing.manifest.json")); !errors.Is(err, ErrUnverifiedCustody) {
		t.Fatalf("missing published manifest accepted: %v", err)
	}
	data := strings.TrimSuffix(manifest, ".manifest.json") + ".jsonl"
	file, err := os.OpenFile(data, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil { t.Fatal(err) }
	_, err = file.WriteString("corruption\n")
	closeErr := file.Close()
	if err != nil || closeErr != nil { t.Fatalf("corrupt fixture: %v %v", err, closeErr) }
	if _, err := ProposeAfterPublishedWindow(cp, journal, window, dir, manifest); !errors.Is(err, ErrUnverifiedCustody) {
		t.Fatalf("spool digest corruption accepted: %v", err)
	}
}

func TestWindowContinuityAndIdentityFailureNeverReadsSpool(t *testing.T) {
	for _, tc := range []struct {
		name string
		change func(*volumeepoch.Checkpoint,*volumeepoch.Journal,*Window)
	}{
		{"wrong epoch", func(_ *volumeepoch.Checkpoint,_ *volumeepoch.Journal,w *Window) {w.Boundary.Epoch++}},
		{"wrong enrollment", func(_ *volumeepoch.Checkpoint,_ *volumeepoch.Journal,w *Window) {w.Boundary.EnrollmentID="system"}},
		{"changed volume", func(_ *volumeepoch.Checkpoint,j *volumeepoch.Journal,_ *Window) {j.Identity.VolumeGUID=testOtherGUID}},
		{"changed journal", func(_ *volumeepoch.Checkpoint,j *volumeepoch.Journal,_ *Window) {j.Identity.JournalID="44"}},
		{"aged out", func(_ *volumeepoch.Checkpoint,j *volumeepoch.Journal,_ *Window) {j.FirstUSN="2400"}},
		{"wrong cursor", func(_ *volumeepoch.Checkpoint,_ *volumeepoch.Journal,w *Window) {w.Boundary.StartUSN="2001"}},
		{"no progression", func(_ *volumeepoch.Checkpoint,_ *volumeepoch.Journal,w *Window) {w.Boundary.NextUSN="2000"}},
		{"past journal", func(_ *volumeepoch.Checkpoint,_ *volumeepoch.Journal,w *Window) {w.Boundary.NextUSN="3001"}},
		{"bad change cursor", func(_ *volumeepoch.Checkpoint,_ *volumeepoch.Journal,w *Window) {w.Changes[0].USN="2501"}},
		{"wrong fact version", func(_ *volumeepoch.Checkpoint,_ *volumeepoch.Journal,w *Window) {w.Changes[0].Version="bad"}},
		{"wrong reference width", func(_ *volumeepoch.Checkpoint,_ *volumeepoch.Journal,w *Window) {w.Changes[0].NTFSRecordVersion=3}},
		{"path masquerading as ID", func(_ *volumeepoch.Checkpoint,_ *volumeepoch.Journal,w *Window) {w.Changes[0].FileReferenceHex="C:\\GovernedRoot"}},
		{"too many", func(_ *volumeepoch.Checkpoint,_ *volumeepoch.Journal,w *Window) {w.Changes=make([]MinimalChange,maxWindowChanges+1)}},
		{"truncated source", func(_ *volumeepoch.Checkpoint,_ *volumeepoch.Journal,w *Window) {w.Boundary.SourceRecordCount=0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c,j,w:=custodyFixture()
			tc.change(&c,&j,&w)
			if _,err:=ProposeAfterPublishedWindow(c,j,w,t.TempDir(),""); !errors.Is(err,ErrUnsafeWindow) {
				t.Fatalf("invalid source boundary was allowed to inspect a manifest: %v",err)
			}
		})
	}
}

func TestWindowPreservesUSNV3IdentityWidthWithoutInventingContainment(t *testing.T) {
	cp,j,w:=custodyFixture()
	w.Changes[0].NTFSRecordVersion=3
	w.Changes[0].FileReferenceHex="00000000000000000000000000000001"
	w.Changes[0].ParentReferenceHex="00000000000000000000000000000002"
	dir:=t.TempDir()
	manifest:=publishFixture(t,dir,w,MinimalFactRecordKind,BoundaryRecordKind,"volume:data")
	next,err:=ProposeAfterPublishedWindow(cp,j,w,dir,manifest)
	if err!=nil||next.NextUSN!="2500" {t.Fatalf("USN V3 fact not retained: %+v %v",next,err)}
}
