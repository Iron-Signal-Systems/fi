// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportwire

import (
	"bytes"
	"testing"
)

func FuzzReadHeader(f *testing.F) {
	_, validHeader, _ := encodedWireTestHeader(f)

	f.Add([]byte{})
	f.Add([]byte(frameMagic))
	f.Add(validHeader)

	f.Fuzz(func(t *testing.T, data []byte) {
		// Keep this target focused on the bounded wire-header parser. Oversized
		// allocations are exercised through encoded length fields; very large raw
		// fuzz inputs add cost without improving that boundary coverage.
		if len(data) > 2*1024*1024 {
			return
		}

		header, err := ReadHeader(bytes.NewReader(data))
		if err != nil {
			return
		}

		// A successful parser return must already satisfy the Header contract.
		if err := header.Validate(); err != nil {
			t.Fatalf(
				"ReadHeader() returned header that fails Validate(): %v",
				err,
			)
		}
	})
}
