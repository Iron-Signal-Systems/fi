// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package ntfs

import (
	"errors"
	"testing"
)

func asciiUTF16(value string) []uint16 {
	units := make([]uint16, len(value))
	for index := range value {
		units[index] = uint16(value[index])
	}
	return units
}

func TestLocalAbsolutePathValidation(t *testing.T) {
	accepted := []string{
		`C:\Data\object.txt`,
		`\\?\C:\Data\object.txt`,
	}
	for _, value := range accepted {
		if err := validateLocalAbsolutePath(asciiUTF16(value)); err != nil {
			t.Fatalf("validateLocalAbsolutePath(%q) = %v", value, err)
		}
	}

	rejected := []string{
		`Data\object.txt`,
		`C:object.txt`,
		`\\server\share\object.txt`,
		`\\?\UNC\server\share\object.txt`,
		`\\?\Volume{11111111-1111-1111-1111-111111111111}\object.txt`,
		`\\?\GLOBALROOT\Device\HarddiskVolume1\object.txt`,
		`\\.\C:\Data\object.txt`,
		`\\.\pipe\fi`,
	}
	for _, value := range rejected {
		err := validateLocalAbsolutePath(asciiUTF16(value))
		if !errors.Is(err, ErrUnsafePathForm) {
			t.Fatalf("validateLocalAbsolutePath(%q) = %v, want ErrUnsafePathForm", value, err)
		}
	}
}

func TestLocalAbsolutePathRejectsNamedStream(t *testing.T) {
	streamPaths := []string{
		`C:\Data\object.txt:payload`,
		`\\?\C:\Data\object.txt:Zone.Identifier`,
	}
	for _, value := range streamPaths {
		err := validateLocalAbsolutePath(asciiUTF16(value))
		if !errors.Is(err, ErrStreamQualifiedPath) {
			t.Fatalf("validateLocalAbsolutePath(%q) = %v, want ErrStreamQualifiedPath", value, err)
		}
	}
}

func TestHandleDerivedContainment(t *testing.T) {
	root := asciiUTF16(`\\?\Volume{11111111-1111-1111-1111-111111111111}\Data`)
	tests := []struct {
		target string
		want   bool
	}{
		{`\\?\Volume{11111111-1111-1111-1111-111111111111}\Data`, true},
		{`\\?\Volume{11111111-1111-1111-1111-111111111111}\Data\object.txt`, true},
		{`\\?\Volume{11111111-1111-1111-1111-111111111111}\Database\object.txt`, false},
		{`\\?\Volume{22222222-2222-2222-2222-222222222222}\Data\object.txt`, false},
	}
	for _, test := range tests {
		if got := pathContainedBy(root, asciiUTF16(test.target)); got != test.want {
			t.Fatalf("pathContainedBy(%q) = %v, want %v", test.target, got, test.want)
		}
	}
}
