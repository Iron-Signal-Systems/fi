// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package ntfs

import "testing"

func TestFinalPathBufferLengthAcceptsBoundedLength(t *testing.T) {
	got, err := finalPathBufferLength(512)
	if err != nil {
		t.Fatal(err)
	}
	if got != 513 {
		t.Fatalf("size = %d, want 513", got)
	}

	got, err = finalPathBufferLength(maximumFinalPathUTF16Units - 1)
	if err != nil {
		t.Fatal(err)
	}
	if got != maximumFinalPathUTF16Units {
		t.Fatalf("size = %d, want %d", got, maximumFinalPathUTF16Units)
	}
}

func TestFinalPathBufferLengthRejectsCeiling(t *testing.T) {
	if _, err := finalPathBufferLength(maximumFinalPathUTF16Units); err == nil {
		t.Fatal("expected final-path allocation ceiling rejection")
	}
}
