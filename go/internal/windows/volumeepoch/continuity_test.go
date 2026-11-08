// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package volumeepoch

import (
	"errors"
	"strings"
	"testing"
)

const guid = `\\?\Volume{18fed846-4275-4251-b698-f268192100f2}\`
const otherGUID = `\\?\Volume{f21d9dd4-8111-4be8-83e9-a1429a261cdf}\`

func fixture() (Checkpoint, Journal) {
	id := Identity{VolumeGUID: guid, VolumeSerial: "15172277115761558407", JournalID: "134367117582369963"}
	return Checkpoint{Version: CheckpointVersion, EnrollmentID: "governed-data-01", Epoch: 7, Identity: id, NextUSN: "2000"},
		Journal{Identity: id, FirstUSN: "1000", LowestValidUSN: "1000", NextUSN: "3000"}
}

func TestAssessContinuityAndNoCheckpoint(t *testing.T) {
	cp, current := fixture()
	tests := []struct {
		name   string
		saved  *Checkpoint
		want   State
		reason Reason
	}{
		{"continuous", &cp, Continuous, ""},
		{"first onboarding", nil, BaselineRequired, NoCheckpoint},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Assess(cp.EnrollmentID, tc.saved, current)
			if err != nil || got.State != tc.want || got.Reason != tc.reason {
				t.Fatalf("Assess()=(%+v,%v), want (%s,%s)", got, err, tc.want, tc.reason)
			}
		})
	}
}

func TestAssessDiscontinuity(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Checkpoint, *Journal)
		want   Reason
	}{
		{"volume GUID changed", func(_ *Checkpoint, j *Journal) { j.Identity.VolumeGUID = otherGUID }, VolumeChanged},
		{"reformatted volume serial", func(_ *Checkpoint, j *Journal) { j.Identity.VolumeSerial = "15172277115761558408" }, VolumeChanged},
		{"same GUID and serial but recreated journal", func(_ *Checkpoint, j *Journal) { j.Identity.JournalID = "134367117582369964" }, JournalChanged},
		{"journal aged out", func(_ *Checkpoint, j *Journal) { j.FirstUSN = "2100"; j.LowestValidUSN = "0" }, JournalAgedOut},
		{"below lowest valid", func(_ *Checkpoint, j *Journal) { j.LowestValidUSN = "2100" }, BeforeLowestValid},
		{"checkpoint ahead", func(c *Checkpoint, j *Journal) { c.NextUSN = "4000" }, AheadOfJournal},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cp, j := fixture()
			tc.change(&cp, &j)
			got, err := Assess(cp.EnrollmentID, &cp, j)
			if err != nil || got.State != Gap || got.Reason != tc.want {
				t.Fatalf("Assess()=(%+v,%v), want Gap/%s", got, err, tc.want)
			}
		})
	}
}

func TestAssessRejectsInvalidPersistentState(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Checkpoint)
		want   error
	}{
		{"version", func(c *Checkpoint) { c.Version = "fi-usn-checkpoint/0.1" }, ErrInvalidCheckpoint},
		{"zero epoch", func(c *Checkpoint) { c.Epoch = 0 }, ErrInvalidCheckpoint},
		{"wrong enrollment", func(c *Checkpoint) { c.EnrollmentID = "other-volume" }, ErrInvalidCheckpoint},
		{"invalid path", func(c *Checkpoint) { c.Identity.VolumeGUID = `\\.\C:` }, ErrInvalidCheckpoint},
		{"invalid serial", func(c *Checkpoint) { c.Identity.VolumeSerial = "-1" }, ErrInvalidCheckpoint},
		{"noncanonical journal", func(c *Checkpoint) { c.Identity.JournalID = "001" }, ErrInvalidCheckpoint},
		{"overflow", func(c *Checkpoint) { c.NextUSN = "18446744073709551616" }, ErrInvalidCheckpoint},
		{"whitespace", func(c *Checkpoint) { c.NextUSN = " 2000" }, ErrInvalidCheckpoint},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cp, j := fixture()
			tc.mutate(&cp)
			_, err := Assess("governed-data-01", &cp, j)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Assess error=%v; want %v", err, tc.want)
			}
		})
	}
}

func TestAssessRejectsMalformedCurrentJournal(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Journal)
	}{
		{"bad journal id", func(j *Journal) { j.Identity.JournalID = "-1" }},
		{"untrusted device", func(j *Journal) { j.Identity.VolumeGUID = `\\.\PhysicalDrive0` }},
		{"first after next", func(j *Journal) { j.FirstUSN = "4000" }},
		{"lowest after next", func(j *Journal) { j.LowestValidUSN = "4000" }},
		{"noncanonical next", func(j *Journal) { j.NextUSN = "03000" }},
		{"overflow", func(j *Journal) { j.NextUSN = "18446744073709551616" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cp, j := fixture()
			tc.mutate(&j)
			_, err := Assess(cp.EnrollmentID, &cp, j)
			if !errors.Is(err, ErrInvalidJournal) {
				t.Fatalf("error=%v; want invalid journal", err)
			}
		})
	}
}

func TestAssessVolumeGUIDCaseInsensitive(t *testing.T) {
	cp, j := fixture()
	j.Identity.VolumeGUID = strings.ToUpper(guid)
	got, err := Assess(cp.EnrollmentID, &cp, j)
	if err != nil || got.State != Continuous {
		t.Fatalf("Assess()=(%+v,%v)", got, err)
	}
}

func TestAssessIndependentVolumes(t *testing.T) {
	first, firstJournal := fixture()
	second, secondJournal := fixture()
	second.EnrollmentID = "system-volume-02"
	second.Identity.VolumeGUID = otherGUID
	secondJournal.Identity.VolumeGUID = otherGUID
	firstJournal.Identity.JournalID = "999999"
	firstResult, firstErr := Assess(first.EnrollmentID, &first, firstJournal)
	secondResult, secondErr := Assess(second.EnrollmentID, &second, secondJournal)
	if firstErr != nil || secondErr != nil || firstResult.State != Gap || secondResult.State != Continuous {
		t.Fatalf("volume isolation first=(%+v,%v) second=(%+v,%v)", firstResult, firstErr, secondResult, secondErr)
	}
}

// A volume enrollment ID may later become part of a state namespace. Reject
// path traversal, casing ambiguity and unbounded IDs even with no checkpoint.
func TestAssessRejectsUnsafeEnrollmentIDs(t *testing.T) {
	cp, journal := fixture()
	for _, id := range []string{"", "../root", "a/b", "MixedCase", "spaces present", "a\nb", strings.Repeat("x", 65)} {
		t.Run(id, func(t *testing.T) {
			if _, err := Assess(id, nil, journal); err == nil {
				t.Fatal("untrusted enrollment ID accepted")
			}
			if _, err := Assess(id, &cp, journal); err == nil {
				t.Fatal("untrusted checkpoint enrollment ID accepted")
			}
		})
	}
}
