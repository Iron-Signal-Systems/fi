// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package ntfs

import "testing"

func TestParentLocalAbsolutePath(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{`C:\`, `C:\`},
		{`C:\one`, `C:\`},
		{`C:\one\two`, `C:\one`},
		{`C:\one\two\`, `C:\one`},
		{`\\?\C:\`, `\\?\C:\`},
		{`\\?\C:\one`, `\\?\C:\`},
		{`\\?\C:\one\two`, `\\?\C:\one`},
	}

	for _, test := range tests {
		got, err := parentLocalAbsolutePath(asciiUTF16(test.input))
		if err != nil {
			t.Fatalf("parentLocalAbsolutePath(%q): %v", test.input, err)
		}
		if stringFromASCIIUTF16(got) != test.want {
			t.Fatalf("parentLocalAbsolutePath(%q) = %q, want %q", test.input, stringFromASCIIUTF16(got), test.want)
		}
	}
}

func stringFromASCIIUTF16(value []uint16) string {
	result := make([]byte, len(value))
	for index := range value {
		result[index] = byte(value[index])
	}
	return string(result)
}
