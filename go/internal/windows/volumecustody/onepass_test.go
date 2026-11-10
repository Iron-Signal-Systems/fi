// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package volumecustody

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/windows/volumeepoch"
)

var errPassFault = errors.New("injected volume one-pass failure")

// passHarness uses the actual FI spool writer and manifest verifier while
// injecting the native source, cross-process lock and persistent checkpoint
// backend. It cannot establish real Windows authorization or durability.
type passHarness struct {
	t              *testing.T
	events         []string
	checked        volumeepoch.Checkpoint
	window         Window
	journal        volumeepoch.Journal
	after          *volumeepoch.Journal
	spoolDir       string
	failAt         string
	queries        int
	loads          int
	publishedPath  string
	savedBefore    volumeepoch.Checkpoint
	ctxCancel      context.CancelFunc
}

func newPassHarness(t *testing.T) *passHarness {
	t.Helper()
	saved, journal, window := custodyFixture()
	return &passHarness{
		t: t, checked: saved, savedBefore: saved, journal: journal,
		window: window, spoolDir: t.TempDir(),
	}
}
func (h *passHarness) event(name string) { h.events = append(h.events, name) }
func (h *passHarness) dep() PassDependencies {
	return PassDependencies{
		Lease: h, Store: h, Source: h, Publisher: h, SpoolDir: h.spoolDir,
	}
}
type passTestLease struct{ owner *passHarness }
func (l *passTestLease) Release() error {
	l.owner.event("release")
	if l.owner.failAt == "release" { return errPassFault }
	return nil
}
func (h *passHarness) Acquire(_ context.Context, enrollmentID string) (Lease, error) {
	h.event("acquire")
	if enrollmentID != h.checked.EnrollmentID { h.t.Fatalf("wrong enrollment lease: %q", enrollmentID) }
	if h.failAt == "lease" { return nil, errPassFault }
	if h.failAt == "nil-lease" { return nil, nil }
	return &passTestLease{owner: h}, nil
}
func (h *passHarness) Load(_ context.Context, id string) (volumeepoch.Checkpoint, error) {
	h.event("load")
	h.loads++
	if id != h.checked.EnrollmentID { h.t.Fatalf("wrong checkpoint enrollment %q", id) }
	if h.failAt == "load" && h.loads == 1 || h.failAt == "reload" && h.loads == 2 {
		return volumeepoch.Checkpoint{}, errPassFault
	}
	if h.failAt == "stale" && h.loads == 2 {
		changed := h.checked
		changed.NextUSN = "2001"
		return changed, nil
	}
	return h.checked, nil
}
func (h *passHarness) Commit(_ context.Context, old, next volumeepoch.Checkpoint) error {
	h.event("commit")
	if h.failAt == "commit" { return errPassFault }
	if old != h.checked || old != h.savedBefore || next.NextUSN != "2500" ||
		next.Identity != old.Identity || next.Epoch != old.Epoch ||
		next.EnrollmentID != old.EnrollmentID {
		return ErrVolumeCheckpointConflict
	}
	h.checked = next
	if h.failAt == "commit-after-write" { return errPassFault }
	return nil
}
func (h *passHarness) QueryJournal(_ context.Context, id string) (volumeepoch.Journal, error) {
	h.event("query")
	h.queries++
	if id != h.checked.EnrollmentID { h.t.Fatalf("wrong journal enrollment %q", id) }
	if h.failAt == "query" && h.queries == 1 ||
		h.failAt == "requery" && h.queries == 2 {
		return volumeepoch.Journal{}, errPassFault
	}
	if h.after != nil && h.queries > 1 { return *h.after, nil }
	return h.journal, nil
}
func (h *passHarness) ReadBounded(_ context.Context, id, cursor string, max uint32) (Window, volumeepoch.Journal, error) {
	h.event("read")
	if id != h.checked.EnrollmentID || cursor != "2000" || max != maxWindowChanges {
		h.t.Fatalf("reader input not enrolled and bounded: id=%q cursor=%q max=%d", id, cursor, max)
	}
	if h.failAt == "read" { return Window{}, volumeepoch.Journal{}, errPassFault }
	if h.ctxCancel != nil { h.ctxCancel() }
	return h.window, h.journal, nil
}
func (h *passHarness) PublishWindow(_ context.Context, window Window) (string, error) {
	h.event("publish")
	if h.failAt == "publish" { return "", errPassFault }
	if h.failAt == "no-manifest" { return "", nil }
	if h.failAt == "mutate-publisher" {
		// An untrusted publisher can alter its input before writing, but
		// the coordinator must verify against the original native capture.
		window.Changes[0].USN = "2201"
	}
	h.publishedPath = publishFixture(h.t, h.spoolDir, window,
		MinimalFactRecordKind, BoundaryRecordKind, "volume:"+window.Boundary.EnrollmentID)
	if h.failAt == "wrong-manifest" {
		return filepath.Join(h.spoolDir, "missing.manifest.json"), nil
	}
	return h.publishedPath, nil
}

func TestOneWindowCoordinatesCustodyThenCheckpointCAS(t *testing.T) {
	h := newPassHarness(t)
	result, err := ProcessOneWindow(context.Background(), "data", h.dep())
	if err != nil { t.Fatal(err) }
	if !result.Published || !result.CommitAttempted || !result.CheckpointCommitted || result.Candidate == nil ||
		result.Candidate.NextUSN != "2500" || result.ManifestPath != h.publishedPath ||
		h.checked.NextUSN != "2500" {
		t.Fatalf("one-pass success not fully accounted: result=%+v saved=%+v", result, h.checked)
	}
	want := []string{"acquire", "load", "query", "read", "publish", "query", "load", "commit", "release"}
	if !reflect.DeepEqual(h.events, want) {
		t.Fatalf("unsafe operation order: got %v want %v", h.events, want)
	}
}

func TestOneWindowFailureGatesDoNotAdvanceCheckpoint(t *testing.T) {
	cases := []struct{
		name string
		failAt string
		change func(*passHarness)
		lastEvent string
		published bool
	}{
		{"lease refusal", "lease", nil, "acquire", false},
		{"nil lease", "nil-lease", nil, "acquire", false},
		{"checkpoint read error", "load", nil, "release", false},
		{"checkpoint malformed", "", func(h *passHarness){h.checked.NextUSN="invalid"}, "release", false},
		{"journal preflight read error", "query", nil, "release", false},
		{"journal discontinuity", "", func(h *passHarness){h.journal.Identity.JournalID="999"}, "release", false},
		{"native read failure", "read", nil, "release", false},
		{"native invalid bounded window", "", func(h *passHarness){h.window.Boundary.NextUSN="3001"}, "release", false},
		{"incomplete publication", "publish", nil, "release", false},
		{"no publication manifest", "no-manifest", nil, "release", false},
		{"publisher mutated validated capture", "mutate-publisher", nil, "release", true},
		{"journal requery failure", "requery", nil, "release", true},
		{"journal replacement after publish", "", func(h *passHarness){
			j := h.journal
			j.Identity.JournalID = "999"
			h.after = &j
		}, "release", true},
		{"manifest mislocated", "wrong-manifest", nil, "release", true},
		{"checkpoint re-read failure", "reload", nil, "release", true},
		{"stale checkpoint", "stale", nil, "release", true},
		{"checkpoint commit failure", "commit", nil, "release", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h:=newPassHarness(t)
			h.failAt=tc.failAt
			if tc.change!=nil {tc.change(h)}
			result,err:=ProcessOneWindow(context.Background(),"data",h.dep())
			if err==nil {t.Fatalf("failure scenario accepted: %+v",result)}
			if result.CheckpointCommitted || result.Published != tc.published ||
				result.CommitAttempted != (tc.failAt == "commit") {
				t.Fatalf("failed pass advanced or misreported source custody: %+v %v",result,err)
			}
			if h.events[len(h.events)-1] != tc.lastEvent {
				t.Fatalf("unexpected last event %v, expected %q",h.events,tc.lastEvent)
			}
			if tc.name != "checkpoint malformed" && h.checked.NextUSN != "2000" {
				t.Fatalf("checkpoint advanced during failure: %+v",h.checked)
			}
			if tc.published && result.ManifestPath == "" {
				t.Fatal("published evidence path was lost during failure")
			}
		})
	}
}

func TestOneWindowNeverAcquiresLeaseForUnsafeOrIncompleteInputs(t *testing.T) {
	h:=newPassHarness(t)
	for _, id:=range []string{"", "../data", "Data", "data/other", "bad space"} {
		_,err:=ProcessOneWindow(context.Background(),id,h.dep())
		if !errors.Is(err,ErrUnconfiguredPass) || len(h.events)!=0 {
			t.Fatalf("invalid enrollment reached external dependency: %q err=%v events=%v",id,err,h.events)
		}
	}
	for _, bad:=range []PassDependencies{
		{}, {Lease:h, Store:h, Source:h, SpoolDir:h.spoolDir},
		{Lease:h, Store:h, Publisher:h, SpoolDir:h.spoolDir},
		{Lease:h, Source:h, Publisher:h, SpoolDir:h.spoolDir},
		{Store:h, Source:h, Publisher:h, SpoolDir:h.spoolDir},
		{Lease:h, Store:h, Source:h, Publisher:h},
	} {
		_,err:=ProcessOneWindow(context.Background(),"data",bad)
		if !errors.Is(err,ErrUnconfiguredPass) || len(h.events)!=0 {
			t.Fatalf("missing dependency reached external I/O: %v events=%v",err,h.events)
		}
	}
}

func TestOneWindowCancellationPreservesCursorAndReleasesLease(t *testing.T) {
	h:=newPassHarness(t)
	ctx,cancel:=context.WithCancel(context.Background())
	defer cancel()
	h.ctxCancel=cancel
	result,err:=ProcessOneWindow(ctx,"data",h.dep())
	if !errors.Is(err,context.Canceled) || result.Published ||
		result.CheckpointCommitted || h.checked.NextUSN!="2000" ||
		!reflect.DeepEqual(h.events,[]string{"acquire","load","query","read","release"}) {
		t.Fatalf("cancelled pass performed writes: result=%+v err=%v events=%v",result,err,h.events)
	}
}

func TestOneWindowReleaseFailureNeverConcealsCommittedState(t *testing.T) {
	h:=newPassHarness(t)
	h.failAt="release"
	result,err:=ProcessOneWindow(context.Background(),"data",h.dep())
	if !errors.Is(err,errPassFault) || !result.Published ||
		!result.CheckpointCommitted || h.checked.NextUSN!="2500" {
		t.Fatalf("lease release error concealed committed state: result=%+v err=%v",result,err)
	}
}

func TestAmbiguousCheckpointWriteReportsInDoubtWithoutInventedRollback(t *testing.T) {
	h:=newPassHarness(t)
	h.failAt="commit-after-write"
	result,err:=ProcessOneWindow(context.Background(),"data",h.dep())
	if !errors.Is(err,errPassFault) || !result.Published ||
		!result.CommitAttempted || result.CheckpointCommitted ||
		result.Candidate==nil || h.checked.NextUSN!="2500" {
		t.Fatalf("ambiguous write concealed actual state or claimed commit: result=%+v err=%v persisted=%+v",result,err,h.checked)
	}
	if h.publishedPath=="" || result.ManifestPath!=h.publishedPath {
		t.Fatal("in-doubt pass lost published spool custody evidence")
	}
}

func TestEarlyCancellationDoesNotAcquireLease(t *testing.T) {
	h:=newPassHarness(t)
	ctx,cancel:=context.WithCancel(context.Background())
	cancel()
	result,err:=ProcessOneWindow(ctx,"data",h.dep())
	if !errors.Is(err,context.Canceled) || len(h.events)!=0 ||
		result.CommitAttempted || result.Published {
		t.Fatalf("cancelled pass reached external resource: %+v %v events=%v",result,err,h.events)
	}
}

func TestFailedVolumeCannotStallIndependentEnrolledVolumePass(t *testing.T) {
	failing:=newPassHarness(t)
	failing.failAt="publish"
	result,err:=ProcessOneWindow(context.Background(),"data",failing.dep())
	if err==nil || result.CheckpointCommitted {t.Fatalf("first volume failure allowed cursor advance: %+v %v",result,err)}

	other:=newPassHarness(t)
	other.checked.EnrollmentID="system"
	other.savedBefore.EnrollmentID="system"
	other.window.Boundary.EnrollmentID="system"
	other.window.Boundary.Identity.VolumeGUID=testOtherGUID
	other.checked.Identity.VolumeGUID=testOtherGUID
	other.savedBefore.Identity.VolumeGUID=testOtherGUID
	other.journal.Identity.VolumeGUID=testOtherGUID
	result,err=ProcessOneWindow(context.Background(),"system",other.dep())
	if err!=nil || !result.CheckpointCommitted || other.checked.NextUSN!="2500" {
		t.Fatalf("independent enrolled volume was blocked by first failure: %+v %v",result,err)
	}
}
