// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package freshinstall

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

const (
	testInstallID  = "bcdef01234567890abcdef0123456789"
	testScopeSHA   = "f1302266d212324eef10ab70ea4c09cb86151de3130d6b9485d4bd60f38a018e"
)

type recordingSink struct {
	data bytes.Buffer
	calls int
	failAt int
	partial bool
}

func (sink *recordingSink) AppendAndSync(frame []byte) error {
	sink.calls++
	if sink.failAt == sink.calls {
		if sink.partial {
			_, _ = sink.data.Write(frame[:len(frame)/2])
		}
		return errors.New("simulated durable journal failure")
	}
	_, err := sink.data.Write(frame)
	return err
}

type recordingCreator struct {
	steps []CreationStep
	failAt int
}

func (creator *recordingCreator) Create(step CreationStep) error {
	creator.steps = append(creator.steps, step)
	if creator.failAt == len(creator.steps) {
		return errors.New("simulated partial native create")
	}
	return nil
}

func validJournal(t *testing.T) ([]byte, []CreationStep) {
	t.Helper()
	var journal recordingSink
	var backend recordingCreator
	if err := executeCreation(&journal, &backend, testInstallID, testScopeSHA); err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), journal.data.Bytes()...), backend.steps
}

func TestCreationJournalCompletePlanRequiresEveryDurableAcknowledgement(t *testing.T) {
	data, steps := validJournal(t)
	if len(steps) != len(creationSteps) {
		t.Fatalf("missing create-only steps: %+v", steps)
	}
	for i := range steps {
		if steps[i] != creationSteps[i] {
			t.Fatalf("created step %d out of order: %s", i, steps[i])
		}
	}
	status, err := InspectCreationJournal(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if !status.Complete || status.InDoubt || status.NextStep != "" ||
		status.CreatedSteps != len(creationSteps) ||
		status.Records != uint64(maxCreationRecords) ||
		status.InstallationID != testInstallID || status.ScopeSHA256 != testScopeSHA {
		t.Fatalf("incorrect completed journal: %+v", status)
	}
	// This is audit evidence ONLY. It must not be usable as an authorization
	// token or proof that any native Windows files/services were installed.
}

func TestCreationNeverMutatesBeforeDurableIntent(t *testing.T) {
	for _, failAt := range []int{1, 2, 4, 7, 14} {
		t.Run(fmt.Sprintf("record%d", failAt), func(t *testing.T) {
			sink := &recordingSink{failAt: failAt}
			backend := &recordingCreator{}
			err := executeCreation(sink, backend, testInstallID, testScopeSHA)
			if !errors.Is(err, ErrCreationInDoubt) {
				t.Fatalf("journal write error did not fail closed: %v", err)
			}
			// Fail at BEGIN => no native step; fail at a particular intent =>
			// no corresponding native Create. After creation but before its
			// acknowledgement, the side effect may already exist and must
			// never be automatically removed or repeated.
			if failAt == 1 && len(backend.steps) != 0 {
				t.Fatal("native create ran without durable Begin")
			}
			if failAt == 2 && len(backend.steps) != 0 {
				t.Fatal("native create ran without durable first intent")
			}
			if failAt == 4 && len(backend.steps) != 1 {
				t.Fatalf("second native create ran without its intent: %+v", backend.steps)
			}
		})
	}
}

func TestCreationFailureLeavesExplicitUnknownOwnership(t *testing.T) {
	for _, failAt := range []int{1, 3, len(creationSteps)} {
		sink := &recordingSink{}
		backend := &recordingCreator{failAt: failAt}
		err := executeCreation(sink, backend, testInstallID, testScopeSHA)
		if !errors.Is(err, ErrCreationInDoubt) {
			t.Fatalf("native mutation failed without uncertain-state error: %v", err)
		}
		status, inspectErr := InspectCreationJournal(bytes.NewReader(sink.data.Bytes()))
		if !errors.Is(inspectErr, ErrCreationInDoubt) || !status.InDoubt ||
			status.CreatedSteps != failAt-1 || status.Complete {
			t.Fatalf("failed native step was represented as committed: %+v %v", status, inspectErr)
		}
		if status.NextStep != creationSteps[failAt-1] {
			t.Fatalf("incorrect next uncertain step: %+v", status)
		}
	}
}

func TestUnacknowledgedCreationAndMissingCompleteNeverImplySuccess(t *testing.T) {
	data, _ := validJournal(t)
	parts := bytes.Split(data[:len(data)-1], []byte{'\n'})
	// After durable intent, the last Create may have happened; without its
	// recorded ack recovery must refuse both automatic retry and delete.
	partial := bytes.Join(parts[:len(parts)-2], []byte{'\n'})
	partial = append(partial, '\n')
	status, err := InspectCreationJournal(bytes.NewReader(partial))
	if !errors.Is(err, ErrCreationInDoubt) || !status.InDoubt || status.Complete {
		t.Fatalf("pending creation accepted: %+v %v", status, err)
	}
	// All native step acknowledgements but missing explicit completion is
	// also ambiguous: commit/manifest persistence may be underway.
	partial = bytes.Join(parts[:len(parts)-1], []byte{'\n'})
	partial = append(partial, '\n')
	status, err = InspectCreationJournal(bytes.NewReader(partial))
	if !errors.Is(err, ErrCreationInDoubt) || status.Complete ||
		status.CreatedSteps != len(creationSteps) {
		t.Fatalf("missing terminal completion accepted: %+v %v", status, err)
	}
}

func TestCreationJournalRejectsMalformedAndTruncatedEvidence(t *testing.T) {
	good, _ := validJournal(t)
	cases := []struct {
		name string
		edit func([]byte) []byte
	}{
		{"nil journal", func([]byte) []byte { return nil }},
		{"missing final newline", func(b []byte) []byte { return b[:len(b)-1] }},
		{"missing record", func(b []byte) []byte {
			lines := bytes.Split(b[:len(b)-1], []byte{'\n'})
			return append(bytes.Join(append(lines[:3:3], lines[4:]...), []byte{'\n'}), '\n')
		}},
		{"appended bytes", func(b []byte) []byte { return append(b, []byte("arbitrary")...) }},
		{"duplicate complete event", func(b []byte) []byte {
			lines := bytes.Split(b[:len(b)-1], []byte{'\n'})
			return append(b, append(lines[len(lines)-1], '\n')...)
		}},
		{"noncanonical whitespace", func(b []byte) []byte { return append([]byte(" "), b...) }},
		{"unknown event field", func(b []byte) []byte {
			lines := bytes.Split(b[:len(b)-1], []byte{'\n'})
			lines[0] = append(lines[0][:len(lines[0])-1], []byte(`,"allow_all":true}`)...)
			return append(bytes.Join(lines, []byte{'\n'}), '\n')
		}},
		{"record tampered", func(b []byte) []byte {
			return bytes.Replace(b, []byte(testInstallID), []byte("abcdef01234567890abcdef012345678"), 1)
		}},
		{"oversized journal", func([]byte) []byte { return bytes.Repeat([]byte{'x'}, maxCreationJournalBytes+1) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			altered := tc.edit(append([]byte(nil), good...))
			if _, err := InspectCreationJournal(bytes.NewReader(altered)); !errors.Is(err, ErrInvalidCreationJournal) {
				t.Fatalf("altered/malformed journal accepted: %v", err)
			}
		})
	}
	if _, err := InspectCreationJournal(nil); !errors.Is(err, ErrInvalidCreationJournal) {
		t.Fatal("missing reader accepted")
	}
}

func TestCreationJournalRejectsRehashedButOutOfOrderOrCrossInstallEvents(t *testing.T) {
	good, _ := validJournal(t)
	raw := bytes.Split(good[:len(good)-1], []byte{'\n'})
	test := func(name string, edit func(*CreationRecord)) {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			var previous string
			for i, line := range raw {
				var item CreationRecord
				if err := json.Unmarshal(line, &item); err != nil { t.Fatal(err) }
				if i == 3 { edit(&item) }
				item.PreviousSHA256 = previous
				encoded, hash, err := encodeCreationRecord(item)
				if err != nil { t.Fatal(err) }
				previous = hash
				out.Write(encoded)
			}
			// The hash chain is not a signature: even a fully recomputed
			// chain must still pass sequence and event-state validation.
			if _, err := InspectCreationJournal(&out); !errors.Is(err, ErrInvalidCreationJournal) {
				t.Fatalf("rehashed invalid journal accepted: %v", err)
			}
		})
	}
	test("duplicate begin", func(r *CreationRecord) { r.Event = CreationBegin; r.Step = "" })
	test("wrong step", func(r *CreationRecord) { r.Step = CommitProtectedState })
	test("cross installation", func(r *CreationRecord) { r.InstallationID = "abcdef01234567890abcdef012345678" })
	test("incorrect sequence", func(r *CreationRecord) { r.Sequence = 101 })
	test("missing matching intent", func(r *CreationRecord) { r.Event = CreationObserved })
}

func TestCreationJournalRefusesInvalidInputsAndNoBackend(t *testing.T) {
	cases := []struct {
		sink CreationSink
		backend CreationBackend
		id string
		digest string
	}{
		{nil, &recordingCreator{}, testInstallID, testScopeSHA},
		{&recordingSink{}, nil, testInstallID, testScopeSHA},
		{&recordingSink{}, &recordingCreator{}, "not-an-id", testScopeSHA},
		{&recordingSink{}, &recordingCreator{}, testInstallID, strings.Repeat("0", 63)},
	}
	for _, tc := range cases {
		if err := executeCreation(tc.sink, tc.backend, tc.id, tc.digest); !errors.Is(err, ErrInvalidCreationJournal) {
			t.Fatalf("invalid create-only caller accepted: %v", err)
		}
	}
}

func TestCreationJournalSinkCanFailAfterPartialDurableWrite(t *testing.T) {
	sink := &recordingSink{failAt: 6, partial: true}
	backend := &recordingCreator{}
	err := executeCreation(sink, backend, testInstallID, testScopeSHA)
	if !errors.Is(err, ErrCreationInDoubt) {
		t.Fatalf("ambiguous partial durable append must block recovery: %v", err)
	}
	if _, err := InspectCreationJournal(bytes.NewReader(sink.data.Bytes())); !errors.Is(err, ErrInvalidCreationJournal) {
		t.Fatalf("partial tail treated as a complete recorded state: %v", err)
	}
}
