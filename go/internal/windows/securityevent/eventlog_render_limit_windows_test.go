// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package securityevent

import "testing"

func TestRenderedEventXMLBufferUnitsRejectsEmptySize(t *testing.T) {
	for _, used := range []uint32{0, 1} {
		if _, err := renderedEventXMLBufferUnits(used); err == nil {
			t.Fatalf("used = %d: expected error", used)
		}
	}
}

func TestRenderedEventXMLBufferUnitsAcceptsBoundedSize(t *testing.T) {
	units, err := renderedEventXMLBufferUnits(maximumRenderedEventXMLBytes)
	if err != nil {
		t.Fatal(err)
	}
	if want := int(maximumRenderedEventXMLBytes / 2); units != want {
		t.Fatalf("units = %d, want %d", units, want)
	}
}

func TestRenderedEventXMLBufferUnitsRejectsOversizedSize(t *testing.T) {
	if _, err := renderedEventXMLBufferUnits(maximumRenderedEventXMLBytes + 1); err == nil {
		t.Fatal("expected oversized render rejection")
	}
}
