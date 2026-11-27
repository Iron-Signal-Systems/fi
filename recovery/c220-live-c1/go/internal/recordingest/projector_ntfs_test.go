// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"bytes"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func TestPrepareContentPrefixProjectionPresentEmpty(t *testing.T) {
	value := records.ContentPrefixObservation{
		State:           records.ContentPrefixPresent,
		BytesObserved:   "0",
		PrefixBase64URL: "",
	}

	bytesObserved, prefix, err :=
		prepareContentPrefixProjection(value)
	if err != nil {
		t.Fatalf(
			"prepareContentPrefixProjection() error = %v",
			err,
		)
	}

	count, ok := bytesObserved.(int16)
	if !ok {
		t.Fatalf(
			"bytesObserved type = %T, want int16",
			bytesObserved,
		)
	}

	if count != 0 {
		t.Fatalf(
			"bytesObserved = %d, want 0",
			count,
		)
	}

	if prefix == nil {
		t.Fatal(
			"prefix = nil, want non-nil zero-length byte slice",
		)
	}

	if len(prefix) != 0 {
		t.Fatalf(
			"prefix length = %d, want 0",
			len(prefix),
		)
	}
}

func TestPrepareContentPrefixProjectionPresentNonEmpty(t *testing.T) {
	value := records.ContentPrefixObservation{
		State:           records.ContentPrefixPresent,
		BytesObserved:   "4",
		PrefixBase64URL: "JVBERg",
	}

	bytesObserved, prefix, err :=
		prepareContentPrefixProjection(value)
	if err != nil {
		t.Fatalf(
			"prepareContentPrefixProjection() error = %v",
			err,
		)
	}

	count, ok := bytesObserved.(int16)
	if !ok {
		t.Fatalf(
			"bytesObserved type = %T, want int16",
			bytesObserved,
		)
	}

	if count != 4 {
		t.Fatalf(
			"bytesObserved = %d, want 4",
			count,
		)
	}

	want := []byte{0x25, 0x50, 0x44, 0x46}

	if !bytes.Equal(prefix, want) {
		t.Fatalf(
			"prefix = %x, want %x",
			prefix,
			want,
		)
	}
}

func TestPrepareContentPrefixProjectionRejectsEmptyMismatch(t *testing.T) {
	value := records.ContentPrefixObservation{
		State:           records.ContentPrefixPresent,
		BytesObserved:   "1",
		PrefixBase64URL: "",
	}

	if _, _, err :=
		prepareContentPrefixProjection(value); err == nil {
		t.Fatal(
			"prepareContentPrefixProjection() accepted empty prefix with bytes_observed=1",
		)
	}
}
