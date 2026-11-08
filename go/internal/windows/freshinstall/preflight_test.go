// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package freshinstall

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

type fakeInspector struct {
	services map[string]Presence
	paths map[string]Presence
	serviceErrors map[string]error
	pathErrors map[string]error
	serviceCalls []string
	pathCalls []string
}

func (f *fakeInspector) Service(name string) (Presence, error) {
	f.serviceCalls = append(f.serviceCalls, name)
	if err := f.serviceErrors[name]; err != nil { return Unknown, err }
	if v, ok := f.services[name]; ok { return v, nil }
	return Absent, nil
}
func (f *fakeInspector) Path(path string) (Presence, error) {
	f.pathCalls = append(f.pathCalls, path)
	if err := f.pathErrors[path]; err != nil { return Unknown, err }
	if v, ok := f.paths[path]; ok { return v, nil }
	return Absent, nil
}

func TestFreshInstallAcceptsOnlyCompleteObservedAbsence(t *testing.T) {
	p := &fakeInspector{}
	report, err := Assess(p)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Clean || report.InstallBlocked || report.Mode != InstallMode ||
		report.Version != ReportVersion || len(report.Findings) != 7 {
		t.Fatalf("incorrect new-install preflight report: %+v", report)
	}
	if !reflect.DeepEqual(p.serviceCalls, []string{
		"FICollector", "FIUSNReader", "FIObjReader", "FICRLRefresher", "FISender",
	}) {
		t.Fatalf("unexpected SCM names checked: %+v", p.serviceCalls)
	}
	if !reflect.DeepEqual(p.pathCalls, []string{
		`C:\Program Files\FI`, `C:\ProgramData\FI`,
	}) {
		t.Fatalf("unexpected FI paths checked: %+v", p.pathCalls)
	}
	for _, finding := range report.Findings {
		if finding.Presence != Absent || finding.Detail != "" {
			t.Fatalf("clean host contains a non-absent state: %+v", finding)
		}
	}
}

func TestFreshInstallRejectsEveryKnownFIService(t *testing.T) {
	for _, name := range serviceNames {
		t.Run(name, func(t *testing.T) {
			p := &fakeInspector{services: map[string]Presence{name: Present}}
			report, err := Assess(p)
			if !errors.Is(err, ErrExistingFI) || report.Clean || !report.InstallBlocked {
				t.Fatalf("existing FI service %s did not block fresh installation: %+v %v", name, report, err)
			}
			if len(p.serviceCalls) != len(serviceNames) || len(p.pathCalls) != len(ownedPaths) {
				t.Fatal("preflight did not inspect every source after discovering a blocker")
			}
			found := false
			for _, item := range report.Findings {
				if item.Target == name && item.Presence == Present { found = true }
			}
			if !found { t.Fatal("report hid the existing service") }
		})
	}
}

func TestFreshInstallRejectsAllExistingOwnedDirectories(t *testing.T) {
	for _, path := range ownedPaths {
		t.Run(path, func(t *testing.T) {
			p := &fakeInspector{paths: map[string]Presence{path: Present}}
			report, err := Assess(p)
			if !errors.Is(err, ErrExistingFI) || !report.InstallBlocked {
				t.Fatalf("existing FI-owned path %s accepted: %+v %v", path, report, err)
			}
		})
	}
}

func TestFreshInstallUnknownNeverMeansAbsent(t *testing.T) {
	cases := []struct{
		name string
		inspector *fakeInspector
	}{
		{"SCM access denied", &fakeInspector{
			serviceErrors: map[string]error{"FIUSNReader": errors.New("access denied")},
		}},
		{"FI state cannot be inspected", &fakeInspector{
			pathErrors: map[string]error{`C:\ProgramData\FI`: errors.New("access denied")},
		}},
		{"unrecognized native status", &fakeInspector{
			services: map[string]Presence{"FICollector": "INVALID"},
		}},
		{"explicit unknown", &fakeInspector{
			paths: map[string]Presence{`C:\ProgramData\FI`: Unknown},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			report, err := Assess(tc.inspector)
			if !errors.Is(err, ErrExistingFI) || !report.InstallBlocked || report.Clean {
				t.Fatalf("uncertain FI evidence was accepted: %+v %v", report, err)
			}
			unknown := false
			for _, item := range report.Findings {
				if item.Presence == Unknown {
					unknown = true
					if strings.TrimSpace(item.Detail) == "" {
						t.Fatal("uncertain native outcome lacks diagnostic reason")
					}
				}
			}
			if !unknown { t.Fatalf("unknown state hidden: %+v", report.Findings) }
		})
	}
}

func TestFreshInstallReportsEveryCollisionInStableOrder(t *testing.T) {
	p := &fakeInspector{
		services: map[string]Presence{"FISender": Present, "FICollector": Present},
		paths: map[string]Presence{`C:\Program Files\FI`: Present},
	}
	a, err := Assess(p)
	if !errors.Is(err, ErrExistingFI) { t.Fatal(err) }
	p2 := &fakeInspector{
		services: map[string]Presence{"FICollector": Present, "FISender": Present},
		paths: map[string]Presence{`C:\Program Files\FI`: Present},
	}
	b, err := Assess(p2)
	if !errors.Is(err, ErrExistingFI) { t.Fatal(err) }
	if !reflect.DeepEqual(a, b) { t.Fatalf("same host produced inconsistent report:\n%+v\n%+v", a, b) }
	total := 0
	for _, item := range a.Findings {
		if item.Presence == Present {
			total++
			if !strings.Contains(item.Detail, "manual disposition") {
				t.Fatalf("existing custody not flagged for manual disposition: %+v", item)
			}
		}
	}
	if total != 3 { t.Fatalf("expected three independent FI collisions, saw %d", total) }
}

func TestFreshInstallRequiresInspector(t *testing.T) {
	if _, err := Assess(nil); err == nil { t.Fatal("missing inspector accepted") }
}

func ExampleAssess() {
	p := &fakeInspector{
		services: map[string]Presence{"FIUSNReader": Present},
	}
	report, err := Assess(p)
	fmt.Println(report.Mode, report.Clean, errors.Is(err, ErrExistingFI))
	// Output: FreshInstallOnly false true
}
