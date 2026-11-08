// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package config

import (
	"bytes"
	"strings"
	"testing"
)

const approvedData = `version_id: 2.0
volume.data.guid = \\?\Volume{18fed846-4275-4251-b698-f268192100f2}\
volume.data.serial = 15172277115761558407
volume.system.guid = \\?\Volume{f21d9dd4-8111-4be8-83e9-a1429a261cdf}\
volume.system.serial = 14888954410052949637
policy.finance.volume = data
policy.finance.root = \Shares\Finance
policy.finance.depth = security
policy.software.volume = system
policy.software.root = \Program Files\SW
policy.software.depth = metadata
`

func TestParseVolumeV2MultiVolume(t *testing.T) {
	v, err := ParseVolumeV2(strings.NewReader(approvedData))
	if err != nil {
		t.Fatal(err)
	}
	if v.Version != VolumeConfigVersion || len(v.Volumes) != 2 || len(v.Policies) != 2 {
		t.Fatalf("invalid plan: %+v", v)
	}
	if v.Volumes[0].ID != "data" || v.Policies[1].VolumeID != "system" {
		t.Fatalf("plan not in canonical order: %+v", v)
	}
	canonical, err := CanonicalVolumeV2(v)
	if err != nil {
		t.Fatal(err)
	}
	if string(canonical) != approvedData {
		t.Fatalf("canonical output differs\n%s", canonical)
	}
	second, err := ParseVolumeV2(bytes.NewReader(canonical))
	if err != nil || !sameVolumeConfig(v, second) {
		t.Fatalf("roundtrip got %+v error %v", second, err)
	}
}

func TestParseVolumeV2AllowsZeroGovernedRoots(t *testing.T) {
	raw := `version_id: 2.0
volume.data.guid = \\?\Volume{18fed846-4275-4251-b698-f268192100f2}\
volume.data.serial = 15172277115761558407
`
	v, err := ParseVolumeV2(strings.NewReader(raw))
	if err != nil || len(v.Volumes) != 1 || len(v.Policies) != 0 {
		t.Fatalf("zero root plan %+v: %v", v, err)
	}
}

func TestParseVolumeV2RejectsUnsafeScope(t *testing.T) {
	tests := []struct{ name, raw, want string }{
		{"no volume", "version_id: 2.0\n", "at least one"},
		{"bad version", strings.Replace(approvedData, "version_id: 2.0", "version_id: 1.1", 1), "first directive"},
		{"duplicate field", approvedData + "volume.data.serial = 2\n", "duplicate"},
		{"unrecognized field", approvedData + "volume.data.everything = true\n", "unknown volume field"},
		{"unknown policy field", approvedData + "policy.finance.unsafe = true\n", "unknown policy field"},
		{"not enrolled", strings.Replace(approvedData, "policy.finance.volume = data", "policy.finance.volume = other", 1), "unenrolled"},
		{"relative traversal", strings.Replace(approvedData, `\Shares\Finance`, `\Shares\..\Windows`, 1), "ambiguous"},
		{"absolute drive path", strings.Replace(approvedData, `\Shares\Finance`, `D:\Shares\Finance`, 1), "volume-relative"},
		{"UNC policy", strings.Replace(approvedData, `\Shares\Finance`, `\\server\share`, 1), "volume-relative"},
		{"policy root trailing separator", strings.Replace(approvedData, `\Shares\Finance`, `\Shares\Finance\`, 1), "trailing"},
		{"bad serial", strings.Replace(approvedData, "15172277115761558407", "0", 1), "serial"},
		{"serial overflow", strings.Replace(approvedData, "15172277115761558407", "18446744073709551616", 1), "serial"},
		{"bad volume locator", strings.Replace(approvedData, `\\?\Volume{18fed846-4275-4251-b698-f268192100f2}\`, `D:\`, 1), "volume guid"},
		{"same volume twice", strings.Replace(approvedData, `\\?\Volume{f21d9dd4-8111-4be8-83e9-a1429a261cdf}\`, `\\?\Volume{18fed846-4275-4251-b698-f268192100f2}\`, 1), "share the same"},
		{"same root twice", approvedData + `policy.second.volume = data` + "\n" + `policy.second.root = \Shares\Finance` + "\n" + `policy.second.depth = content` + "\n", "same root"},
		{"root missing depth", strings.Replace(approvedData, "policy.finance.depth = security\n", "", 1), "requires"},
		{"nul in root", strings.Replace(approvedData, `\Shares\Finance`, "\\Shares\\Finance"+string(rune(0)), 1), "control character"},
		{"tab in path", strings.Replace(approvedData, `\Shares\Finance`, "\\Shares\\Fin\tance", 1), "control character"},
		{"invalid UTF-8 path", strings.Replace(approvedData, `\Shares\Finance`, "\\Shares\\Fin"+string([]byte{0xff}), 1), "valid UTF-8"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseVolumeV2(strings.NewReader(tc.raw))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got error %v, want %s", err, tc.want)
			}
		})
	}
}

func TestCanonicalVolumeV2RefusesNoncanonicalOrMutatedModel(t *testing.T) {
	v, err := ParseVolumeV2(strings.NewReader(approvedData))
	if err != nil {
		t.Fatal(err)
	}
	v.Policies[0].RelativeRoot = `\Shares\..\Wrong`
	if _, err := CanonicalVolumeV2(v); err == nil {
		t.Fatal("roundtrip must reject unsafe path")
	}
	v, err = ParseVolumeV2(strings.NewReader(approvedData))
	if err != nil {
		t.Fatal(err)
	}
	v.Volumes[0].Serial = "0001"
	if _, err := CanonicalVolumeV2(v); err == nil {
		t.Fatal("roundtrip must reject noncanonical serial")
	}
}

func TestParseVolumeV2CanonicalOrdering(t *testing.T) {
	lines := strings.Split(strings.TrimSpace(approvedData), "\n")
	reordered := []string{lines[0]}
	for i := len(lines) - 1; i >= 1; i-- {
		reordered = append(reordered, lines[i])
	}
	parsed, err := ParseVolumeV2(strings.NewReader(strings.Join(reordered, "\n") + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := CanonicalVolumeV2(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if string(canonical) != approvedData {
		t.Fatalf("canonical output is nondeterministic: %s", canonical)
	}
}
