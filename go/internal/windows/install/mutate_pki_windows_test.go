// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"testing"
	"unsafe"
)

func TestCertEnrollHRESULTClassification(
	t *testing.T,
) {
	t.Parallel()

	if certEnrollHRESULTFailed(0) {
		t.Fatal(
			"S_OK was classified as failure",
		)
	}

	if certEnrollHRESULTFailed(1) {
		t.Fatal(
			"S_FALSE was classified as failure",
		)
	}

	if !certEnrollHRESULTFailed(
		uintptr(
			uint32(0x80004005),
		),
	) {
		t.Fatal(
			"E_FAIL was not classified as failure",
		)
	}
}

func TestCertEnrollVariantABI(
	t *testing.T,
) {
	t.Parallel()

	expected := uintptr(16)
	if unsafe.Sizeof(
		uintptr(0),
	) == 8 {
		expected = 24
	}

	actual := unsafe.Sizeof(
		certEnrollVariant{},
	)

	if actual != expected {
		t.Fatalf(
			"VARIANT ABI size=%d want=%d",
			actual,
			expected,
		)
	}
}
