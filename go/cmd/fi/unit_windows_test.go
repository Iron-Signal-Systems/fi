// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/checkpoint"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/operation"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/securityevent"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/supportingstate"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/usn"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestCurrentDomainTokenSIDs(t *testing.T) {
	identity := records.ProcessIdentityObservation{
		Computer: records.ComputerIdentity{NetBIOSName: "ADMINBOX", DNSDomain: "iss.local"},
		Token: records.ProcessTokenObservation{
			User: records.TokenPrincipalObservation{SID: "S-1-5-21-1-2-3-1106", DomainName: "ISS"},
			Groups: []records.TokenGroupObservation{
				{Principal: records.TokenPrincipalObservation{SID: "S-1-5-21-1-2-3-512"}},
				{Principal: records.TokenPrincipalObservation{SID: "S-1-5-32-544"}},
				{Principal: records.TokenPrincipalObservation{SID: "S-1-5-21-1-2-3-513"}},
			},
		},
	}

	got := currentDomainTokenSIDs(identity)
	want := []string{
		"S-1-5-21-1-2-3-1106",
		"S-1-5-21-1-2-3-512",
		"S-1-5-21-1-2-3-513",
	}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestAccountDomainSIDPrefixRejectsNonDomainSID(t *testing.T) {
	if _, ok := accountDomainSIDPrefix("S-1-5-32-544"); ok {
		t.Fatal("expected BUILTIN SID rejection")
	}
}

func TestCurrentDomainTokenSIDsRejectsLocalAccount(t *testing.T) {
	identity := records.ProcessIdentityObservation{
		Computer: records.ComputerIdentity{NetBIOSName: "ADMINBOX", DNSDomain: "iss.local"},
		Token: records.ProcessTokenObservation{
			User: records.TokenPrincipalObservation{SID: "S-1-5-21-9-8-7-1001", DomainName: "ADMINBOX"},
		},
	}
	if got := currentDomainTokenSIDs(identity); len(got) != 0 {
		t.Fatalf("local account produced domain SIDs: %#v", got)
	}
}

func TestCurrentDomainRelatedSIDsIncludesLocalMembershipDomainSID(t *testing.T) {
	identity := records.ProcessIdentityObservation{}
	identity.Computer.NetBIOSName = "SERVER1"
	identity.Token.User.DomainName = "ISS"
	identity.Token.User.SID = "S-1-5-21-1-2-3-1106"
	identity.Token.Groups = append(identity.Token.Groups, records.TokenGroupObservation{
		Principal: records.TokenPrincipalObservation{SID: "S-1-5-21-1-2-3-513"},
	})
	local := records.LocalPrincipalSnapshot{Memberships: []records.LocalGroupMembershipObservation{
		{GroupSID: "S-1-5-32-544", MemberSID: "S-1-5-21-1-2-3-2100"},
		{GroupSID: "S-1-5-32-545", MemberSID: "S-1-1-0"},
	}}
	got := currentDomainRelatedSIDs(identity, local, true)
	want := []string{"S-1-5-21-1-2-3-1106", "S-1-5-21-1-2-3-2100", "S-1-5-21-1-2-3-513"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}

func TestValidateBaselineSpoolForCheckpointComplete(t *testing.T) {
	summary := spoolRunSummary{
		FileObservations: 2,
		Batches:          []spool.FinalizedBatch{{}, {}},
		VerifiedBatches:  2,
	}
	if err := validateBaselineSpoolForCheckpoint(summary); err != nil {
		t.Fatalf("complete baseline rejected: %v", err)
	}
}

func TestValidateBaselineSpoolForCheckpointRejectsCollectionError(t *testing.T) {
	summary := spoolRunSummary{
		FileObservations: 2,
		CollectionErrors: 1,
		Batches:          []spool.FinalizedBatch{{}},
		VerifiedBatches:  1,
	}
	if err := validateBaselineSpoolForCheckpoint(summary); !errors.Is(err, ErrBaselineCollectionIncomplete) {
		t.Fatalf("error = %v", err)
	}
}

func TestValidateBaselineSpoolForCheckpointRejectsHashError(t *testing.T) {
	summary := spoolRunSummary{
		FileObservations: 2,
		HashErrors:       1,
		Batches:          []spool.FinalizedBatch{{}},
		VerifiedBatches:  1,
	}
	if err := validateBaselineSpoolForCheckpoint(summary); !errors.Is(err, ErrBaselineCollectionIncomplete) {
		t.Fatalf("error = %v", err)
	}
}

func TestValidateBaselineSpoolForCheckpointRejectsUnverifiedBatch(t *testing.T) {
	summary := spoolRunSummary{
		FileObservations: 2,
		Batches:          []spool.FinalizedBatch{{}, {}},
		VerifiedBatches:  1,
	}
	if err := validateBaselineSpoolForCheckpoint(summary); !errors.Is(err, ErrBaselineCollectionIncomplete) {
		t.Fatalf("error = %v", err)
	}
}

func TestWriteBaselineRootStreamsObjectsBeforeDirectoryResolution(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "sample.txt"), []byte("sample"), 0o600); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	if err := writeBaselineRoot(context.Background(), &output, root); err != nil {
		t.Fatal(err)
	}

	scanner := bufio.NewScanner(bytes.NewReader(output.Bytes()))
	events := []baselineEvent{}
	for scanner.Scan() {
		var event baselineEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatalf("decode baseline line: %v\n%s", err, scanner.Text())
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}

	if len(events) < 5 {
		t.Fatalf("baseline emitted %d events, want at least 5", len(events))
	}

	if events[0].Kind != baselineKindCollectorIdentity || events[0].CollectorIdentity == nil {
		t.Fatalf("first event = %+v, want collector identity", events[0])
	}

	if events[1].Kind != baselineKindSMBShareSnapshot {
		t.Fatalf("second event kind = %q, want %q", events[1].Kind, baselineKindSMBShareSnapshot)
	}
	if events[1].SMBShareSnapshot == nil && events[1].Error == "" {
		t.Fatal("SMB share event contains neither snapshot nor explicit error")
	}

	if events[2].Kind != baselineKindLocalPrincipals {
		t.Fatalf("third event kind = %q, want %q", events[2].Kind, baselineKindLocalPrincipals)
	}
	if events[2].LocalPrincipals == nil && events[2].Error == "" {
		t.Fatal("local principal event contains neither snapshot nor explicit error")
	}

	last := events[len(events)-1]
	if last.Kind != baselineKindDirectoryPrincipals {
		t.Fatalf("last event kind = %q, want %q", last.Kind, baselineKindDirectoryPrincipals)
	}
	if last.DirectoryPrincipals == nil && last.Error == "" {
		t.Fatal("directory principal event contains neither snapshot nor explicit error")
	}

	foundObject := false
	for _, event := range events[3 : len(events)-1] {
		if event.Kind != baselineKindNTFSObservation {
			t.Fatalf("unexpected event kind %q between baseline context and directory resolution", event.Kind)
		}
		if event.PathDisplay == "" || event.PathUTF16LEBase64URL == "" {
			t.Fatalf("NTFS event missing path identity: %+v", event)
		}
		if event.Observation != nil {
			foundObject = true
		}
	}
	if !foundObject {
		t.Fatal("baseline emitted no successful NTFS observations")
	}
}

func TestAddNTFSObservationSIDsIncludesSecurityAndSACL(t *testing.T) {
	set := newObservedSIDSet()
	observation := ntfs.Observation{
		Security: records.SecurityObservation{
			OwnerSID:        "S-1-5-21-1-2-3-1106",
			PrimaryGroupSID: "S-1-5-21-1-2-3-513",
			DACL: records.ACLObservation{ACEs: []records.ACEObservation{
				{SID: "S-1-5-21-1-2-3-2100"},
				{SID: "S-1-1-0"},
			}},
		},
		SACL: records.SACLObservation{
			ACL: records.ACLObservation{ACEs: []records.ACEObservation{
				{SID: "S-1-5-21-1-2-3-2200"},
			}},
		},
	}

	addNTFSObservationSIDs(set, observation)
	for _, sid := range []string{
		"S-1-5-21-1-2-3-1106",
		"S-1-5-21-1-2-3-513",
		"S-1-5-21-1-2-3-2100",
		"S-1-1-0",
		"S-1-5-21-1-2-3-2200",
	} {
		if _, ok := set.values[sid]; !ok {
			t.Fatalf("SID %s was not gathered", sid)
		}
	}
}

func TestCurrentDomainObservedSIDsFiltersOtherSIDNamespaces(t *testing.T) {
	identity := records.ProcessIdentityObservation{
		Computer: records.ComputerIdentity{NetBIOSName: "SERVER1", DNSDomain: "iss.local"},
		Token: records.ProcessTokenObservation{
			User: records.TokenPrincipalObservation{
				SID:        "S-1-5-21-1-2-3-1106",
				DomainName: "ISS",
			},
		},
	}
	observed := map[string]struct{}{
		"S-1-5-21-1-2-3-1106": {},
		"S-1-5-21-1-2-3-2100": {},
		"S-1-5-21-9-8-7-2100": {},
		"S-1-5-32-544":        {},
		"S-1-1-0":             {},
	}

	got := currentDomainObservedSIDs(identity, observed)
	want := []string{
		"S-1-5-21-1-2-3-1106",
		"S-1-5-21-1-2-3-2100",
	}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}

func TestAppendConfiguredOperationOmitsZeroRecord(t *testing.T) {
	operations := []records.OperationRecord{}
	operations = appendConfiguredOperation(operations, records.OperationRecord{})
	if len(operations) != 0 {
		t.Fatalf("operations = %d, want 0", len(operations))
	}
}

func TestRunConfiguredOperationPreDurableStartFailureReturnsNoSummaryRecord(t *testing.T) {
	root := t.TempDir()
	stateFile := filepath.Join(root, "not-a-directory")
	if err := os.WriteFile(stateFile, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FI_STATE_DIR", stateFile)

	bodyCalled := false
	record, err := runConfiguredOperation(
		"scope-test",
		records.OperationBaseline,
		func() error {
			bodyCalled = true
			return nil
		},
	)
	if err == nil {
		t.Fatal("expected durable-start failure")
	}
	if bodyCalled {
		t.Fatal("operation body ran before Started could be durably appended")
	}
	if record.OperationID != "" {
		t.Fatalf("operation_id = %q, want empty", record.OperationID)
	}
	if got := appendConfiguredOperation(nil, record); len(got) != 0 {
		t.Fatalf("summary operations = %d, want 0", len(got))
	}
}

func TestRunConfiguredOperationBodyFailureReturnsValidFailedRecord(t *testing.T) {
	t.Setenv("FI_STATE_DIR", t.TempDir())

	record, err := runConfiguredOperation(
		"scope-test",
		records.OperationBaseline,
		func() error { return errors.New("boom") },
	)
	if err == nil {
		t.Fatal("expected body failure")
	}
	if record.OperationID == "" {
		t.Fatal("durably started operation returned empty operation ID")
	}
	if record.Outcome != records.OperationFailed {
		t.Fatalf("outcome = %q, want %q", record.Outcome, records.OperationFailed)
	}
	if err := records.ValidateOperationRecord(record); err != nil {
		t.Fatal(err)
	}
	if got := appendConfiguredOperation(nil, record); len(got) != 1 {
		t.Fatalf("summary operations = %d, want 1", len(got))
	}
}

func TestRunConfiguredOperationComplete(t *testing.T) {
	t.Setenv("FI_STATE_DIR", t.TempDir())
	record, err := runConfiguredOperation("scope-a", records.OperationBaseline, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if record.Outcome != records.OperationComplete || record.ReasonCode != "" {
		t.Fatalf("unexpected record: %+v", record)
	}
	path, _ := operation.DefaultJournalPath("scope-a")
	entries, err := operation.ReadAll(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Event != operation.JournalStarted || entries[1].Event != operation.JournalFinished {
		t.Fatalf("unexpected journal entries: %+v", entries)
	}
}

func TestRunConfiguredOperationFailed(t *testing.T) {
	t.Setenv("FI_STATE_DIR", t.TempDir())
	record, err := runConfiguredOperation("scope-a", records.OperationUSNCatchUp, func() error { return errors.New("synthetic failure") })
	if err == nil {
		t.Fatal("expected operation body failure")
	}
	if record.Outcome != records.OperationFailed || record.ReasonCode != "USNCatchUpFailed" {
		t.Fatalf("unexpected record: %+v", record)
	}
}

func TestRecoverConfiguredOperations(t *testing.T) {
	t.Setenv("FI_STATE_DIR", t.TempDir())
	path, _ := operation.DefaultJournalPath("scope-a")
	started, err := operation.Start("scope-a", records.OperationReconciliation)
	if err != nil {
		t.Fatal(err)
	}
	if err := operation.AppendStarted(path, started); err != nil {
		t.Fatal(err)
	}
	journalPath, recovered, err := recoverConfiguredOperations("scope-a")
	if err != nil {
		t.Fatal(err)
	}
	if journalPath != path {
		t.Fatalf("journal path=%q want=%q", journalPath, path)
	}
	if len(recovered) != 1 || recovered[0].Outcome != records.OperationInterrupted || recovered[0].ReasonCode != "ProcessRestart" {
		t.Fatalf("unexpected recovery: %+v", recovered)
	}
}

func TestNextConfiguredSecurityWindowEndUsesBoundedSpan(t *testing.T) {
	start := uint64(100)
	target := start + securityevent.MaxReadRecordIDSpan + 25
	got := nextConfiguredSecurityWindowEnd(start, target)
	want := start + securityevent.MaxReadRecordIDSpan
	if got != want {
		t.Fatalf("window end = %d, want %d", got, want)
	}
}

func TestNextConfiguredSecurityWindowEndUsesShortFinalWindow(t *testing.T) {
	start := uint64(100)
	target := start + 25
	if got := nextConfiguredSecurityWindowEnd(start, target); got != target {
		t.Fatalf("window end = %d, want %d", got, target)
	}
}

func TestNextConfiguredSecurityWindowEndDoesNotAdvancePastTarget(t *testing.T) {
	if got := nextConfiguredSecurityWindowEnd(100, 100); got != 100 {
		t.Fatalf("window end = %d, want 100", got)
	}
	if got := nextConfiguredSecurityWindowEnd(101, 100); got != 100 {
		t.Fatalf("window end = %d, want 100", got)
	}
}

func TestConfiguredScopeIDEquivalentWindowsRoots(t *testing.T) {
	left := configuredScopeID(`D:\Shares\Finance`)
	right := configuredScopeID(`d:\shares\finance\`)
	if left != right {
		t.Fatalf("equivalent roots produced different scope IDs: %q != %q", left, right)
	}
}

func TestConfiguredScopeIDStableValue(t *testing.T) {
	const want = "root-1940386f154d3646c73ddbc054e4555a"
	if got := configuredScopeID(`D:\Shares\Finance`); got != want {
		t.Fatalf("scope ID = %q, want %q", got, want)
	}
}

func TestConfiguredScopeIDDifferentRoots(t *testing.T) {
	finance := configuredScopeID(`D:\Shares\Finance`)
	hr := configuredScopeID(`D:\Shares\HR`)
	if finance == hr {
		t.Fatalf("different roots produced same scope ID: %q", finance)
	}
}

func TestCompareUSN(t *testing.T) {
	tests := []struct {
		name  string
		left  string
		right string
		want  int
	}{
		{name: "less", left: "100", right: "101", want: -1},
		{name: "equal", left: "101", right: "101", want: 0},
		{name: "greater", left: "102", right: "101", want: 1},
		{name: "large", left: "9223372036854710272", right: "718844848", want: 1},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := compareUSN(test.left, test.right)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("compareUSN(%q, %q) = %d, want %d", test.left, test.right, got, test.want)
			}
		})
	}
}

func TestCompareUSNRejectsMalformedValue(t *testing.T) {
	if _, err := compareUSN("not-a-usn", "1"); err == nil {
		t.Fatal("expected malformed USN error")
	}
}

func TestAddPerformanceObservation(t *testing.T) {
	report := performanceReport{
		Collection: performanceCollection{
			WarningCodes: map[string]uint64{},
			ErrorStages:  map[string]uint64{},
		},
	}

	observation := ntfs.Observation{
		GovernedRoot: records.GovernedRootIdentity{
			VolumeIdentity: records.VolumeIdentity{
				VolumeGUID:   `\\?\Volume{00000000-0000-0000-0000-000000000000}\`,
				VolumeSerial: "42",
			},
			ObjectIdentity: records.NTFSObjectIdentity{
				FileReferenceNumber: "100",
				SequenceNumber:      "2",
			},
		},
		SubjectKind: records.SubjectFile,
		Reparse: records.ReparseObservation{
			State: records.ReparseStatePresent,
		},
		StreamInventory: records.StreamInventory{
			Streams: []records.StreamObservation{
				{Identity: records.StreamIdentity{Kind: records.StreamDefaultData}},
				{Identity: records.StreamIdentity{Kind: records.StreamNamedData}},
			},
		},
		ObservationStatus: records.ObservationPartial,
		Warnings: []records.ObservationWarning{
			{Code: "StreamEnumerationFailed"},
		},
	}

	addPerformanceObservation(&report, observation)

	if report.Collection.Observations != 1 || report.Collection.Files != 1 {
		t.Fatalf("unexpected object counts: %+v", report.Collection)
	}
	if report.Collection.NamedDataStreams != 1 || report.Collection.DefaultDataStreams != 1 {
		t.Fatalf("unexpected stream counts: %+v", report.Collection)
	}
	if report.Collection.ReparseObjects != 1 || report.Collection.Partial != 1 {
		t.Fatalf("unexpected state counts: %+v", report.Collection)
	}
	if report.Collection.WarningCodes["StreamEnumerationFailed"] != 1 {
		t.Fatalf("unexpected warning counts: %+v", report.Collection.WarningCodes)
	}
	if report.Root.VolumeSerial != "42" || report.Root.FileReferenceNumber != "100" {
		t.Fatalf("root identity was not recorded: %+v", report.Root)
	}
}

func TestUnsignedDelta(t *testing.T) {
	if got := unsignedDelta(15, 10); got != 5 {
		t.Fatalf("delta = %d, want 5", got)
	}
	if got := unsignedDelta(5, 10); got != 0 {
		t.Fatalf("underflow delta = %d, want 0", got)
	}
}

func TestFinishSupportingSourceRefreshOperationPublishesOnlyAfterDurableAppend(t *testing.T) {
	started, err := operation.Start(
		supportingSourceRefreshScopeID,
		records.OperationSupportingSourceRefresh,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Passing a directory path forces AppendFinished to fail on Windows. The
	// helper must not return an in-memory terminal record that was never made
	// durable in the lifecycle journal.
	record, err := finishSupportingSourceRefreshOperation(
		t.TempDir(),
		started,
		records.OperationComplete,
		"",
	)
	if err == nil {
		t.Fatal("expected terminal journal append failure")
	}
	if record != nil {
		t.Fatalf("undurable terminal record was published: %#v", record)
	}
}

func TestFinishSupportingSourceRefreshOperationReturnsDurableRecord(t *testing.T) {
	started, err := operation.Start(
		supportingSourceRefreshScopeID,
		records.OperationSupportingSourceRefresh,
	)
	if err != nil {
		t.Fatal(err)
	}

	journalPath := filepath.Join(t.TempDir(), "supporting-refresh-operations.jsonl")
	record, err := finishSupportingSourceRefreshOperation(
		journalPath,
		started,
		records.OperationComplete,
		"",
	)
	if err != nil {
		t.Fatal(err)
	}
	if record == nil {
		t.Fatal("durable terminal record was not returned")
	}

	entries, err := operation.ReadAll(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("journal entries = %d, want 1", len(entries))
	}
	if entries[0].Event != operation.JournalFinished {
		t.Fatalf("journal event = %q, want %q", entries[0].Event, operation.JournalFinished)
	}
	if entries[0].OperationID != record.OperationID {
		t.Fatalf("journal operation_id = %q, want %q", entries[0].OperationID, record.OperationID)
	}
}

func TestSupportingSourceRefreshOperationKind(t *testing.T) {
	value := validOperationRecordForSupportingRefreshTest()
	if err := records.ValidateOperationRecord(value); err != nil {
		t.Fatal(err)
	}
}

func TestSupportingSourceRefreshLive(t *testing.T) {
	if os.Getenv("FI_LIVE_SUPPORTING_REFRESH") != "1" {
		t.Skip("set FI_LIVE_SUPPORTING_REFRESH=1 to run the live source refresh")
	}

	summary, err := writeSupportingSourceRefresh(context.Background())
	raw, marshalErr := json.MarshalIndent(summary, "", "  ")
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	t.Log(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	if summary.Status != supportingSourceRefreshComplete &&
		summary.Status != supportingSourceRefreshPartial {
		t.Fatalf("refresh status = %q", summary.Status)
	}
	if summary.RecoveredOperations == nil {
		t.Fatal("refresh returned null recovered_operations")
	}
	if summary.Operation == nil {
		t.Fatal("refresh did not return an operation record")
	}
	if summary.Operation.Kind != records.OperationSupportingSourceRefresh {
		t.Fatalf("operation kind = %q", summary.Operation.Kind)
	}
	if summary.VerifiedBatches != len(summary.Batches) {
		t.Fatalf(
			"verified batches = %d, batches = %d",
			summary.VerifiedBatches,
			len(summary.Batches),
		)
	}
	if summary.SupportingSIDStatePath == "" {
		t.Fatal("refresh did not report supporting SID state path")
	}
	if summary.SupportingSIDCountAfter < summary.SupportingSIDCountBefore {
		t.Fatalf(
			"supporting SID count shrank: %d -> %d",
			summary.SupportingSIDCountBefore,
			summary.SupportingSIDCountAfter,
		)
	}
}

func validOperationRecordForSupportingRefreshTest() records.OperationRecord {
	return records.OperationRecord{
		OperationID: "op-0123456789abcdef0123456789abcdef",
		ScopeID:     supportingSourceRefreshScopeID,
		Kind:        records.OperationSupportingSourceRefresh,
		StartedAt:   "2026-08-26T17:00:00.000000000Z",
		FinishedAt:  "2026-08-26T17:00:01.000000000Z",
		Outcome:     records.OperationComplete,
	}
}

func TestSaveSupportingSIDStateMergesCurrentDomainSIDs(t *testing.T) {
	stateDir := t.TempDir()
	old := os.Getenv("FI_STATE_DIR")
	if err := os.Setenv("FI_STATE_DIR", stateDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if old == "" {
			_ = os.Unsetenv("FI_STATE_DIR")
			return
		}
		_ = os.Setenv("FI_STATE_DIR", old)
	})

	identity := records.ProcessIdentityObservation{
		Computer: records.ComputerIdentity{
			NetBIOSName: "SERVER1",
			DNSFQDN:     "server1.iss.local",
			DNSDomain:   "iss.local",
		},
		Token: records.ProcessTokenObservation{
			User: records.TokenPrincipalObservation{
				SID:        "S-1-5-21-1-2-3-1106",
				DomainName: "ISS",
			},
		},
	}

	observed := newObservedSIDSet()
	observed.add("S-1-5-21-1-2-3-1106")
	observed.add("S-1-5-21-1-2-3-2200")
	observed.add("S-1-5-32-544")
	observed.add("S-1-1-0")

	path, count, err := saveSupportingSIDState(identity, observed)
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(stateDir, supportingstate.DefaultStateFileName) {
		t.Fatalf("path = %q", path)
	}
	if count != 2 {
		t.Fatalf("count = %d, want 2", count)
	}

	state, err := supportingstate.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"S-1-5-21-1-2-3-1106",
		"S-1-5-21-1-2-3-2200",
	}
	if !reflect.DeepEqual(state.RelevantSIDs, want) {
		t.Fatalf("relevant SIDs = %#v, want %#v", state.RelevantSIDs, want)
	}
}

func TestSaveSupportingSIDStateNotApplicableForLocalToken(t *testing.T) {
	identity := records.ProcessIdentityObservation{
		Computer: records.ComputerIdentity{
			NetBIOSName: "SERVER1",
			DNSFQDN:     "server1.iss.local",
			DNSDomain:   "iss.local",
		},
		Token: records.ProcessTokenObservation{
			User: records.TokenPrincipalObservation{
				SID:        "S-1-5-21-9-8-7-1001",
				DomainName: "SERVER1",
			},
		},
	}

	path, count, err := saveSupportingSIDState(identity, newObservedSIDSet())
	if err != nil {
		t.Fatal(err)
	}
	if path != "" || count != 0 {
		t.Fatalf("local token state = (%q, %d), want empty/not-applicable", path, count)
	}
}

func TestAppendSupportingSourceStartSnapshots(t *testing.T) {
	writer := newSupportingSourceTestWriter(t)

	shares := records.SMBShareSnapshot{}
	local := records.LocalPrincipalSnapshot{}
	supporting := supportingSourceContext{
		CollectorIdentity: records.ProcessIdentityObservation{},
		SMBShareSnapshot:  &shares,
		LocalPrincipals:   &local,
		ObservedSIDs:      newObservedSIDSet(),
	}
	var summary spoolRunSummary

	if err := appendSupportingSourceStart(
		writer,
		"scope-test",
		supporting,
		&summary,
	); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	if summary.CollectorIdentityRecords != 1 {
		t.Fatalf("collector identity records = %d, want 1", summary.CollectorIdentityRecords)
	}
	if summary.SMBShareSnapshotRecords != 1 {
		t.Fatalf("SMB records = %d, want 1", summary.SMBShareSnapshotRecords)
	}
	if summary.LocalPrincipalRecords != 1 {
		t.Fatalf("local principal records = %d, want 1", summary.LocalPrincipalRecords)
	}
	if summary.SupportingSourceErrors != 0 {
		t.Fatalf("supporting source errors = %d, want 0", summary.SupportingSourceErrors)
	}
}

func TestAppendSupportingSourceStartPreservesExplicitErrors(t *testing.T) {
	writer := newSupportingSourceTestWriter(t)

	supporting := supportingSourceContext{
		CollectorIdentity:   records.ProcessIdentityObservation{},
		SMBShareError:       "SMBUnavailable",
		LocalPrincipalError: "LocalIdentityUnavailable",
		ObservedSIDs:        newObservedSIDSet(),
	}
	var summary spoolRunSummary

	if err := appendSupportingSourceStart(
		writer,
		"scope-test",
		supporting,
		&summary,
	); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	if summary.CollectorIdentityRecords != 1 {
		t.Fatalf("collector identity records = %d, want 1", summary.CollectorIdentityRecords)
	}
	if summary.SMBShareSnapshotRecords != 0 {
		t.Fatalf("SMB records = %d, want 0", summary.SMBShareSnapshotRecords)
	}
	if summary.LocalPrincipalRecords != 0 {
		t.Fatalf("local principal records = %d, want 0", summary.LocalPrincipalRecords)
	}
	if summary.SupportingSourceErrors != 2 {
		t.Fatalf("supporting source errors = %d, want 2", summary.SupportingSourceErrors)
	}

	data := readOnlyFinalizedDataFile(t, writer)
	if !strings.Contains(data, `"record_kind":"SupportingSourceCollectionError"`) {
		t.Fatal("supporting-source error record was not written")
	}
	if !strings.Contains(data, `"source":"SMBShareSnapshot"`) {
		t.Fatal("SMB source error was not preserved")
	}
	if !strings.Contains(data, `"source":"LocalPrincipalSnapshot"`) {
		t.Fatal("local identity source error was not preserved")
	}
}

func TestAppendDirectorySourceSnapshotAndError(t *testing.T) {
	t.Run("snapshots", func(t *testing.T) {
		writer := newSupportingSourceTestWriter(t)
		var summary spoolRunSummary

		if err := appendDirectorySource(
			writer,
			"scope-test",
			directorySourceResult{
				Snapshots: []records.DirectoryPrincipalSnapshot{{}, {}},
			},
			&summary,
		); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}

		if summary.DirectoryPrincipalRecords != 2 {
			t.Fatalf("directory records = %d, want 2", summary.DirectoryPrincipalRecords)
		}
		if summary.SupportingSourceErrors != 0 {
			t.Fatalf("supporting source errors = %d, want 0", summary.SupportingSourceErrors)
		}
	})

	t.Run("partial-success-before-error", func(t *testing.T) {
		writer := newSupportingSourceTestWriter(t)
		var summary spoolRunSummary

		if err := appendDirectorySource(
			writer,
			"scope-test",
			directorySourceResult{
				Snapshots: []records.DirectoryPrincipalSnapshot{{}},
				Error:     "DirectoryUnavailable",
			},
			&summary,
		); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}

		if summary.DirectoryPrincipalRecords != 1 {
			t.Fatalf("directory records = %d, want 1", summary.DirectoryPrincipalRecords)
		}
		if summary.SupportingSourceErrors != 1 {
			t.Fatalf("supporting source errors = %d, want 1", summary.SupportingSourceErrors)
		}

		data := readOnlyFinalizedDataFile(t, writer)
		if !strings.Contains(data, `"record_kind":"DirectoryPrincipalSnapshot"`) {
			t.Fatal("completed directory source snapshot was not preserved")
		}
		if !strings.Contains(data, `"source":"DirectoryPrincipalSnapshot"`) {
			t.Fatal("directory source error was not preserved")
		}
	})
}

func newSupportingSourceTestWriter(t *testing.T) *spool.Writer {
	t.Helper()

	writer, err := spool.NewWriter(
		t.TempDir(),
		64,
		spool.CollectorIdentity{
			ExecutablePath:   `C:\test\fi.exe`,
			ExecutableSHA256: strings.Repeat("0", 64),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return writer
}

func readOnlyFinalizedDataFile(t *testing.T, writer *spool.Writer) string {
	t.Helper()

	batches := writer.FinalizedBatches()
	if len(batches) != 1 {
		t.Fatalf("finalized batches = %d, want 1", len(batches))
	}

	path := filepath.Clean(batches[0].DataPath)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestCollectDirectorySourceRejectsMissingObservedSIDSet(t *testing.T) {
	identity := directoryTestIdentity()

	result := collectDirectorySource(nil, identity, nil)
	if len(result.Snapshots) != 0 {
		t.Fatalf("missing observed SID set returned %d directory snapshots", len(result.Snapshots))
	}
	if result.Error != "DirectoryObservedSIDsUnavailable" {
		t.Fatalf("error = %q, want DirectoryObservedSIDsUnavailable", result.Error)
	}
}

func TestCollectDirectorySourceRejectsEmptyDomainSIDSetWithoutLDAP(t *testing.T) {
	identity := directoryTestIdentity()
	observed := newObservedSIDSet()
	observed.add("S-1-1-0")
	observed.add("S-1-5-32-544")

	called := false
	result := collectDirectorySourceWithCollector(
		context.Background(),
		identity,
		observed,
		func(context.Context, string, []string) (records.DirectoryPrincipalSnapshot, error) {
			called = true
			return records.DirectoryPrincipalSnapshot{}, nil
		},
	)
	if called {
		t.Fatal("LDAP collector was called for a non-domain SID set")
	}
	if len(result.Snapshots) != 0 {
		t.Fatalf("non-domain SID set returned %d directory snapshots", len(result.Snapshots))
	}
	if result.Error != "DirectoryDomainSIDsUnavailable" {
		t.Fatalf("error = %q, want DirectoryDomainSIDsUnavailable", result.Error)
	}
}

func TestCollectDirectorySourceBatchesLargeRelevantSIDSet(t *testing.T) {
	identity := directoryTestIdentity()
	observed := newObservedSIDSet()
	for index := 0; index < directorySIDBatchSize+1; index++ {
		observed.add(fmt.Sprintf("S-1-5-21-1-2-3-%d", 1000+index))
	}

	var batchSizes []int
	result := collectDirectorySourceWithCollector(
		context.Background(),
		identity,
		observed,
		func(_ context.Context, domain string, sids []string) (records.DirectoryPrincipalSnapshot, error) {
			if domain != "iss.local" {
				t.Fatalf("domain = %q, want iss.local", domain)
			}
			batchSizes = append(batchSizes, len(sids))
			return records.DirectoryPrincipalSnapshot{
				RequestedSIDs: append([]string(nil), sids...),
			}, nil
		},
	)
	if result.Error != "" {
		t.Fatalf("directory source error = %q", result.Error)
	}
	if len(result.Snapshots) != 2 {
		t.Fatalf("snapshots = %d, want 2", len(result.Snapshots))
	}
	if len(batchSizes) != 2 || batchSizes[0] != directorySIDBatchSize || batchSizes[1] != 1 {
		t.Fatalf("batch sizes = %#v, want [%d 1]", batchSizes, directorySIDBatchSize)
	}
}

func TestCollectDirectorySourcePreservesCompletedBatchBeforeFailure(t *testing.T) {
	identity := directoryTestIdentity()
	observed := newObservedSIDSet()
	for index := 0; index < directorySIDBatchSize+1; index++ {
		observed.add(fmt.Sprintf("S-1-5-21-1-2-3-%d", 2000+index))
	}

	calls := 0
	result := collectDirectorySourceWithCollector(
		context.Background(),
		identity,
		observed,
		func(_ context.Context, _ string, sids []string) (records.DirectoryPrincipalSnapshot, error) {
			calls++
			if calls == 2 {
				return records.DirectoryPrincipalSnapshot{}, errors.New("second LDAP batch failed")
			}
			return records.DirectoryPrincipalSnapshot{
				RequestedSIDs: append([]string(nil), sids...),
			}, nil
		},
	)
	if len(result.Snapshots) != 1 {
		t.Fatalf("snapshots = %d, want 1 completed snapshot", len(result.Snapshots))
	}
	if result.Error != "second LDAP batch failed" {
		t.Fatalf("error = %q", result.Error)
	}
}

func TestLoadSupportingSIDStateMissingRequiresDurableBaseline(t *testing.T) {
	t.Setenv("FI_STATE_DIR", t.TempDir())

	statePath, count, err := loadSupportingSIDState(
		directoryTestIdentity(),
		newObservedSIDSet(),
	)
	if err == nil {
		t.Fatal("missing supporting SID state returned no error")
	}
	if statePath == "" {
		t.Fatal("missing supporting SID state did not report its expected path")
	}
	if count != 0 {
		t.Fatalf("missing supporting SID state count = %d, want 0", count)
	}
	if !strings.Contains(err.Error(), "complete a durable baseline") {
		t.Fatalf("error = %q, want durable-baseline prerequisite", err)
	}
}

func directoryTestIdentity() records.ProcessIdentityObservation {
	return records.ProcessIdentityObservation{
		Computer: records.ComputerIdentity{
			NetBIOSName: "SERVER1",
			DNSDomain:   "iss.local",
		},
		Token: records.ProcessTokenObservation{
			User: records.TokenPrincipalObservation{
				SID:        "S-1-5-21-1-2-3-1106",
				DomainName: "ISS",
			},
		},
	}
}

func TestNewUSNContinuityGapObservation(t *testing.T) {
	assessment := checkpoint.ContinuityAssessment{
		CheckedAt:  "2026-08-26T12:00:00.1234567Z",
		Status:     checkpoint.ContinuityGap,
		ReasonCode: "JournalIDChanged",
		Checkpoint: checkpoint.USNCheckpoint{
			ScopeID:   "root-a",
			JournalID: "10",
			NextUSN:   "20",
		},
		JournalState: records.USNJournalState{
			JournalID:      "11",
			FirstUSN:       "30",
			LowestValidUSN: "30",
			NextUSN:        "40",
		},
	}

	value, err := newUSNContinuityGapObservation(`C:\Data`, assessment)
	if err != nil {
		t.Fatal(err)
	}
	if value.ObservedAt != "2026-08-26T12:00:00.123456700Z" {
		t.Fatalf("observed_at=%q", value.ObservedAt)
	}
	if err := records.ValidateUSNContinuityGapObservation(value); err != nil {
		t.Fatal(err)
	}
	if value.ReasonCode != "JournalIDChanged" ||
		value.CheckpointNextUSN != "20" ||
		value.CurrentNextUSN != "40" ||
		value.ReconciliationAction != records.USNContinuityGapReconcileBaselineAndCatchUp {
		t.Fatalf("unexpected gap observation: %+v", value)
	}
}

func TestValidateUSNNextBatch(t *testing.T) {
	assessment, batch := testUSNNextState()

	if err := validateUSNNextBatch(assessment, batch); err != nil {
		t.Fatalf("valid batch rejected: %v", err)
	}
}

func TestValidateUSNNextBatchRejectsJournalChange(t *testing.T) {
	assessment, batch := testUSNNextState()
	batch.JournalID = "778"

	if err := validateUSNNextBatch(assessment, batch); err == nil {
		t.Fatal("journal change accepted")
	}
}

func TestValidateUSNNextBatchRejectsWrongStart(t *testing.T) {
	assessment, batch := testUSNNextState()
	batch.StartUSN = "151"

	if err := validateUSNNextBatch(assessment, batch); err == nil {
		t.Fatal("wrong start USN accepted")
	}
}

func TestValidateUSNNextBatchRejectsGap(t *testing.T) {
	assessment, batch := testUSNNextState()
	assessment.Status = checkpoint.ContinuityGap
	assessment.ReasonCode = "CheckpointAgedOut"

	if err := validateUSNNextBatch(assessment, batch); !errors.Is(err, ErrUSNContinuityGap) {
		t.Fatalf("error = %v, want ErrUSNContinuityGap", err)
	}
}

func testUSNNextState() (checkpoint.ContinuityAssessment, records.USNReadBatch) {
	volume := records.VolumeIdentity{
		MethodVersion: "windows-file-id-info-ntfs/0.1",
		VolumeGUID:    `\\?\Volume{6d8101b5-0000-0000-0000-501f00000000}\`,
		VolumeSerial:  "5528245215150056436",
	}

	root := records.GovernedRootIdentity{
		ScopeID:        "manual-test",
		VolumeIdentity: volume,
		ObjectIdentity: records.NTFSObjectIdentity{
			MethodVersion:       "windows-file-id-info-ntfs/0.1",
			FileReferenceNumber: "42",
			SequenceNumber:      "8",
		},
	}

	value := checkpoint.USNCheckpoint{
		Version:      checkpoint.SchemaVersion,
		ScopeID:      "manual-test",
		GovernedRoot: root,
		JournalID:    "777",
		NextUSN:      "150",
		UpdatedAt:    "2026-08-23T20:00:00Z",
	}

	assessment := checkpoint.ContinuityAssessment{
		Status:     checkpoint.ContinuityContinuous,
		Checkpoint: value,
	}

	batch := records.USNReadBatch{
		ScopeID:        "manual-test",
		VolumeIdentity: volume,
		JournalID:      "777",
		StartUSN:       "150",
		NextUSN:        "175",
	}

	return assessment, batch
}

func testIdentity(record, sequence string) records.NTFSObjectIdentity {
	return records.NTFSObjectIdentity{
		MethodVersion:       ntfs.IdentityMethodVersion,
		FileReferenceNumber: record,
		SequenceNumber:      sequence,
	}
}

func TestGroupUSNChangesPreservesPerObjectOrder(t *testing.T) {
	first := testIdentity("10", "2")
	second := testIdentity("20", "3")

	input := []records.USNChangeObservation{
		{FileIdentity: first, USN: "100"},
		{FileIdentity: second, USN: "101"},
		{FileIdentity: first, USN: "102"},
	}
	grouped := groupUSNChanges(input)

	got := []string{grouped[first][0].USN, grouped[first][1].USN}
	want := []string{"100", "102"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("first object USNs = %v, want %v", got, want)
	}
	if len(grouped[second]) != 1 || grouped[second][0].USN != "101" {
		t.Fatalf("second object changes = %#v", grouped[second])
	}
}

func TestSelectUSNObjectCurrentObjectContained(t *testing.T) {
	object := testIdentity("30", "1")
	root := testIdentity("40", "1")
	called := false

	selection, keep := selectUSNObjectForSpool(
		usn.ChangeReobservation{
			FileIdentity: object,
			Status:       usn.ReobservationObserved,
			Observation:  &ntfs.Observation{},
		},
		[]records.USNChangeObservation{{FileIdentity: object, ParentIdentity: testIdentity("50", "1")}},
		root,
		func(records.NTFSObjectIdentity) parentScopeResult {
			called = true
			return parentScopeResult{Status: parentScopeOutside}
		},
	)

	if !keep {
		t.Fatal("current contained object was not selected")
	}
	if selection.ScopeBasis != scopeBasisCurrentObjectContained {
		t.Fatalf("scope basis = %q", selection.ScopeBasis)
	}
	if called {
		t.Fatal("parent checker was called for an already-contained object")
	}
}

func TestSelectUSNObjectRecordedRootParentContained(t *testing.T) {
	object := testIdentity("60", "1")
	root := testIdentity("70", "2")

	selection, keep := selectUSNObjectForSpool(
		usn.ChangeReobservation{FileIdentity: object, Status: usn.ReobservationOutsideGovernedRoot},
		[]records.USNChangeObservation{{FileIdentity: object, ParentIdentity: root}},
		root,
		func(records.NTFSObjectIdentity) parentScopeResult {
			t.Fatal("parent checker should not be needed when USN parent is the governed root")
			return parentScopeResult{}
		},
	)

	if !keep || selection.ScopeBasis != scopeBasisRecordedParentContained {
		t.Fatalf("selection = %#v, keep=%v", selection, keep)
	}
}

func TestSelectUSNObjectNestedRecordedParentContained(t *testing.T) {
	object := testIdentity("80", "1")
	root := testIdentity("90", "1")
	parent := testIdentity("91", "1")

	selection, keep := selectUSNObjectForSpool(
		usn.ChangeReobservation{FileIdentity: object, Status: usn.ReobservationUnavailable},
		[]records.USNChangeObservation{{FileIdentity: object, ParentIdentity: parent}},
		root,
		func(identity records.NTFSObjectIdentity) parentScopeResult {
			if identity != parent {
				t.Fatalf("checked parent = %#v", identity)
			}
			return parentScopeResult{Status: parentScopeContained}
		},
	)

	if !keep || selection.ScopeBasis != scopeBasisRecordedParentContained {
		t.Fatalf("selection = %#v, keep=%v", selection, keep)
	}
}

func TestSelectUSNObjectUnrelatedVolumeObjectIgnored(t *testing.T) {
	object := testIdentity("100", "1")
	root := testIdentity("110", "1")
	parent := testIdentity("120", "1")

	selection, keep := selectUSNObjectForSpool(
		usn.ChangeReobservation{FileIdentity: object, Status: usn.ReobservationOutsideGovernedRoot},
		[]records.USNChangeObservation{{FileIdentity: object, ParentIdentity: parent}},
		root,
		func(records.NTFSObjectIdentity) parentScopeResult {
			return parentScopeResult{Status: parentScopeOutside}
		},
	)

	if keep {
		t.Fatalf("unrelated volume object was selected: %#v", selection)
	}
}

func TestSelectUSNObjectUnavailableParentDoesNotForceSelection(t *testing.T) {
	object := testIdentity("130", "1")
	root := testIdentity("140", "1")
	parent := testIdentity("150", "1")

	_, keep := selectUSNObjectForSpool(
		usn.ChangeReobservation{FileIdentity: object, Status: usn.ReobservationUnavailable},
		[]records.USNChangeObservation{{FileIdentity: object, ParentIdentity: parent}},
		root,
		func(records.NTFSObjectIdentity) parentScopeResult {
			return parentScopeResult{Status: parentScopeUnavailable}
		},
	)

	if keep {
		t.Fatal("object with no provable governed-root binding should have been ignored")
	}
}

func TestSelectUSNObjectScopeCheckErrorIncluded(t *testing.T) {
	object := testIdentity("160", "1")
	root := testIdentity("170", "1")
	parent := testIdentity("180", "1")

	selection, keep := selectUSNObjectForSpool(
		usn.ChangeReobservation{FileIdentity: object, Status: usn.ReobservationError},
		[]records.USNChangeObservation{{FileIdentity: object, ParentIdentity: parent}},
		root,
		func(records.NTFSObjectIdentity) parentScopeResult {
			return parentScopeResult{Status: parentScopeError, Error: "scope probe failed"}
		},
	)

	if !keep {
		t.Fatal("unresolved object was silently dropped")
	}
	if selection.ScopeBasis != scopeBasisUnresolvedIncluded || selection.ScopeDetail != "scope probe failed" {
		t.Fatalf("selection = %#v", selection)
	}
}

func TestMergeSupportingSIDStateOnlyWritesNewSIDs(t *testing.T) {
	stateDir := t.TempDir()
	oldState := os.Getenv("FI_STATE_DIR")
	if err := os.Setenv("FI_STATE_DIR", stateDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if oldState == "" {
			_ = os.Unsetenv("FI_STATE_DIR")
			return
		}
		_ = os.Setenv("FI_STATE_DIR", oldState)
	})

	identity := records.ProcessIdentityObservation{
		Computer: records.ComputerIdentity{
			NetBIOSName: "SERVER1",
			DNSFQDN:     "server1.iss.local",
			DNSDomain:   "iss.local",
		},
		Token: records.ProcessTokenObservation{
			User: records.TokenPrincipalObservation{
				SID:        "S-1-5-21-1-2-3-1106",
				DomainName: "ISS",
			},
		},
	}

	first := newObservedSIDSet()
	first.add("S-1-5-21-1-2-3-1106")
	first.add("S-1-1-0")

	result, err := mergeSupportingSIDState(identity, first)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Updated || result.CountBefore != 0 || result.CountAfter != 1 {
		t.Fatalf("first merge = %#v", result)
	}
	if result.Path != filepath.Join(
		stateDir,
		supportingstate.DefaultStateFileName,
	) {
		t.Fatalf("state path = %q", result.Path)
	}

	result, err = mergeSupportingSIDState(identity, first)
	if err != nil {
		t.Fatal(err)
	}
	if result.Updated || result.CountBefore != 1 || result.CountAfter != 1 {
		t.Fatalf("unchanged merge = %#v", result)
	}

	second := newObservedSIDSet()
	second.add("S-1-5-21-1-2-3-2200")

	result, err = mergeSupportingSIDState(identity, second)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Updated || result.CountBefore != 1 || result.CountAfter != 2 {
		t.Fatalf("second merge = %#v", result)
	}
}

func TestMergeUSNObservedSIDsIgnoresUnavailableObservation(t *testing.T) {
	selected := []selectedUSNObject{
		{
			Reobservation: usn.ChangeReobservation{
				Status: usn.ReobservationUnavailable,
				Observation: &ntfs.Observation{
					Security: records.SecurityObservation{
						OwnerSID: "S-1-5-21-1-2-3-9999",
					},
				},
			},
		},
	}

	observed := newObservedSIDSet()
	for _, selection := range selected {
		reobservation := selection.Reobservation
		if reobservation.Status != usn.ReobservationObserved ||
			reobservation.Observation == nil {
			continue
		}
		addNTFSObservationSIDs(observed, *reobservation.Observation)
	}
	if len(observed.values) != 0 {
		t.Fatalf("unavailable observation contributed SIDs: %#v", observed.values)
	}
}

func TestUSNObservedSIDExtractionIncludesOwnerDACLAndSACL(t *testing.T) {
	observation := ntfs.Observation{
		Security: records.SecurityObservation{
			OwnerSID:        "S-1-5-21-1-2-3-1100",
			PrimaryGroupSID: "S-1-5-21-1-2-3-513",
			DACL: records.ACLObservation{
				ACEs: []records.ACEObservation{
					{SID: "S-1-5-21-1-2-3-2200"},
				},
			},
		},
		SACL: records.SACLObservation{
			ACL: records.ACLObservation{
				ACEs: []records.ACEObservation{
					{SID: "S-1-5-21-1-2-3-3300"},
				},
			},
		},
	}

	set := newObservedSIDSet()
	addNTFSObservationSIDs(set, observation)

	for _, sid := range []string{
		"S-1-5-21-1-2-3-1100",
		"S-1-5-21-1-2-3-513",
		"S-1-5-21-1-2-3-2200",
		"S-1-5-21-1-2-3-3300",
	} {
		if _, exists := set.values[sid]; !exists {
			t.Fatalf("missing SID %s", sid)
		}
	}
}

func TestNewWindowsSecurityContinuityGapObservation(t *testing.T) {
	assessment := securityevent.ContinuityAssessment{
		Status:     securityevent.ContinuityGap,
		ReasonCode: "SecurityLogRecordsOverwritten",
		Checkpoint: securityevent.Checkpoint{
			LastEventRecordID: "100",
		},
		LogState: securityevent.LogState{
			ObservedAt:          "2026-08-26T12:00:00.1234567Z",
			Channel:             "Security",
			OldestEventRecordID: "200",
			NewestEventRecordID: "300",
		},
	}

	value, err := newWindowsSecurityContinuityGapObservation(assessment)
	if err != nil {
		t.Fatal(err)
	}
	if value.ObservedAt != "2026-08-26T12:00:00.123456700Z" {
		t.Fatalf("observed_at=%q", value.ObservedAt)
	}
	if value.CheckpointEventRecordID != "100" ||
		value.CurrentOldestEventRecordID != "200" ||
		value.CurrentNewestEventRecordID != "300" ||
		value.ReconciliationAction != records.WindowsSecurityContinuityGapReconcileCurrentStateBaseline {
		t.Fatalf("unexpected gap observation: %+v", value)
	}
	if err := records.ValidateWindowsSecurityContinuityGapObservation(value); err != nil {
		t.Fatal(err)
	}
}
func TestConfiguredUSNPassesPartialOnReobservationError(t *testing.T) {
	passes := []usnSpoolNextSummary{{ReobservationErrors: 1}}
	if !configuredUSNPassesPartial(passes) {
		t.Fatal("re-observation error did not make configured USN passes partial")
	}
}

func TestConfiguredUSNPassesPartialOnHashError(t *testing.T) {
	passes := []usnSpoolNextSummary{{HashErrors: 1}}
	if !configuredUSNPassesPartial(passes) {
		t.Fatal("content-hash error did not make configured USN passes partial")
	}
}

func TestConfiguredUSNPassesUnavailableObjectIsNotPartial(t *testing.T) {
	passes := []usnSpoolNextSummary{{UnavailableObjects: 1}}
	if configuredUSNPassesPartial(passes) {
		t.Fatal("normal object unavailability incorrectly made configured USN passes partial")
	}
}

func TestConfiguredUSNPassesScopeUnresolvedIsNotPartialByItself(t *testing.T) {
	passes := []usnSpoolNextSummary{{ScopeUnresolvedObjects: 1}}
	if configuredUSNPassesPartial(passes) {
		t.Fatal("explicit scope uncertainty incorrectly became an operational collection failure")
	}
}
func TestParseServiceInterval(t *testing.T) {
	got, err := parseServiceInterval("test-interval", "2m")
	if err != nil {
		t.Fatal(err)
	}
	if got != 2*time.Minute {
		t.Fatalf("interval = %s, want 2m", got)
	}

	for _, value := range []string{"", "0s", "-1s", "not-a-duration"} {
		if _, err := parseServiceInterval("test-interval", value); err == nil {
			t.Fatalf("value %q unexpectedly accepted", value)
		}
	}
}

func TestServiceRuntimeLogPathUsesFIStateDir(t *testing.T) {
	stateDir := t.TempDir()
	t.Setenv("FI_STATE_DIR", stateDir)

	got, err := serviceRuntimeLogPath()
	if err != nil {
		t.Fatal(err)
	}

	want := filepath.Join(stateDir, serviceRuntimeLogName)
	if got != want {
		t.Fatalf("path = %q, want %q", got, want)
	}
}

func TestRunServiceLoopStartsCollectionImmediatelyAndStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	collected := make(chan struct{}, 1)
	done := make(chan error, 1)

	go func() {
		done <- runServiceLoop(
			ctx,
			time.Hour,
			time.Hour,
			func(context.Context) (configuredRunSummary, error) {
				select {
				case collected <- struct{}{}:
				default:
				}
				return configuredRunSummary{
					ConfiguredRoots: 1,
					CompletedRoots:  1,
					Complete:        true,
				}, nil
			},
			func(context.Context) (supportingSourceRefreshSummary, error) {
				return supportingSourceRefreshSummary{
					Status: supportingSourceRefreshComplete,
				}, nil
			},
			func(serviceRuntimeRecord) error {
				return nil
			},
		)
	}()

	select {
	case <-collected:
	case <-time.After(2 * time.Second):
		t.Fatal("service loop did not run configured collection immediately")
	}

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("service loop did not stop after context cancellation")
	}
}

func TestRunServiceLoopSchedulesSupportingRefreshWithoutOverlap(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	active := 0
	refreshRan := make(chan struct{}, 1)
	done := make(chan error, 1)

	go func() {
		done <- runServiceLoop(
			ctx,
			time.Hour,
			20*time.Millisecond,
			func(context.Context) (configuredRunSummary, error) {
				active++
				if active != 1 {
					t.Errorf("collector overlap detected: active=%d", active)
				}
				time.Sleep(10 * time.Millisecond)
				active--
				return configuredRunSummary{
					ConfiguredRoots: 1,
					CompletedRoots:  1,
					Complete:        true,
				}, nil
			},
			func(context.Context) (supportingSourceRefreshSummary, error) {
				active++
				if active != 1 {
					t.Errorf("supporting-refresh overlap detected: active=%d", active)
				}
				active--
				select {
				case refreshRan <- struct{}{}:
				default:
				}
				return supportingSourceRefreshSummary{
					Status: supportingSourceRefreshComplete,
				}, nil
			},
			func(serviceRuntimeRecord) error {
				return nil
			},
		)
	}()

	select {
	case <-refreshRan:
	case <-time.After(2 * time.Second):
		t.Fatal("supporting refresh was not scheduled")
	}

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("service loop did not stop")
	}
}
