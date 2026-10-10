// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import "testing"

func TestProfileForBuild(t *testing.T) {
	tests := []struct {
		build uint32
		name  string
		ok    bool
	}{
		{build: 14393, name: "Windows Server 2016", ok: true},
		{build: 17763, name: "Windows Server 2019", ok: true},
		{build: 20348, name: "Windows Server 2022", ok: true},
		{build: 26100, name: "Windows Server 2025", ok: true},
		{build: 99999, name: "not_known", ok: false},
	}

	for _, test := range tests {
		profile, ok := ProfileForBuild(test.build)
		if ok != test.ok {
			t.Fatalf("build %d supported = %t, want %t", test.build, ok, test.ok)
		}
		if profile.BuildNumber != test.build {
			t.Fatalf(
				"build %d profile build = %d, want %d",
				test.build,
				profile.BuildNumber,
				test.build,
			)
		}
		if profile.Name != test.name {
			t.Fatalf(
				"build %d profile name = %q, want %q",
				test.build,
				profile.Name,
				test.name,
			)
		}
	}
}

func TestInstallerMutationSupportedBuild(t *testing.T) {
	tests := []struct {
		build uint32
		want  bool
	}{
		{build: 14393, want: true},
		{build: 17763, want: true},
		{build: 20348, want: true},
		{build: 26100, want: true},
		{build: 99999, want: false},
	}

	for _, test := range tests {
		got := installerMutationSupportedBuild(
			test.build,
		)
		if got != test.want {
			t.Fatalf(
				"build %d mutation supported=%t want=%t",
				test.build,
				got,
				test.want,
			)
		}
	}
}

func TestObjReaderRightsMutationEnabledBuild(t *testing.T) {
	tests := []struct {
		build uint32
		want  bool
	}{
		{build: 14393, want: true},
		{build: 17763, want: true},
		{build: 20348, want: false},
		{build: 26100, want: false},
		{build: 99999, want: false},
	}

	for _, test := range tests {
		got := objReaderRightsMutationEnabledBuild(
			test.build,
		)
		if got != test.want {
			t.Fatalf(
				"build %d ObjReader mutation enabled=%t want=%t",
				test.build,
				got,
				test.want,
			)
		}
	}
}
