// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package process

import "testing"

func TestTokenInformationBufferSizeAcceptsBoundedSize(t *testing.T) {
	got, err := tokenInformationBufferSize(maximumTokenInformationBuffer)
	if err != nil {
		t.Fatal(err)
	}
	if got != int(maximumTokenInformationBuffer) {
		t.Fatalf("size = %d, want %d", got, maximumTokenInformationBuffer)
	}
}

func TestTokenInformationBufferSizeRejectsInvalidSize(t *testing.T) {
	if _, err := tokenInformationBufferSize(0); err == nil {
		t.Fatal("expected zero-size rejection")
	}
	if _, err := tokenInformationBufferSize(maximumTokenInformationBuffer + 1); err == nil {
		t.Fatal("expected oversized token-buffer rejection")
	}
}
